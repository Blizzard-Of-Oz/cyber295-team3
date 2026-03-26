import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ImmuDBLogger } from "./immudb-logger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.MCP_HTTP_PORT || 5001;
const DEBUG = process.env.DEBUG === "true";
const OPA_ENABLED = process.env.OPA_ENABLED !== "false";
const OPA_DECISION_URL =
  process.env.OPA_DECISION_URL || "http://localhost:8181/v1/data/gmail/decision";
const OPA_TIMEOUT_MS = process.env.OPA_TIMEOUT_MS ? Number(process.env.OPA_TIMEOUT_MS) : 2000;
const OPA_FAIL_OPEN = process.env.OPA_FAIL_OPEN === "true";
const UC29_THRESHOLD_EMAILS_24H = Number(process.env.UC29_THRESHOLD_EMAILS_24H || 4);
const UC29_THRESHOLD_EMAILS_1H = Number(process.env.UC29_THRESHOLD_EMAILS_1H || 3);

function debugLog(message, meta) {
  if (!DEBUG) return;
  if (meta !== undefined) {
    console.log(`[gmail-mcp-http][debug] ${message}`, meta);
  } else {
    console.log(`[gmail-mcp-http][debug] ${message}`);
  }
}

app.use(express.json({ limit: "1mb" }));

function resolveDefaultMcpCommand() {
  const localServerPath = path.resolve(
    __dirname,
    "..",
    "..",
    "mcp-server",
    "gmail",
    "dist",
    "index.js"
  );
  return {
    command: process.env.MCP_COMMAND || "node",
    args: process.env.MCP_ARGS
      ? process.env.MCP_ARGS.split(" ").filter(Boolean)
      : [localServerPath]
  };
}

class McpClientManager {
  constructor() {
    this.client = null;
    this.transport = null;
    this.tools = null;
    this.connecting = null;
  }

  async connect() {
    if (this.client && this.tools) return;
    if (this.connecting) return this.connecting;

    this.connecting = (async () => {
      const { command, args } = resolveDefaultMcpCommand();
      debugLog("Starting MCP stdio transport", { command, args });
      this.transport = new StdioClientTransport({ command, args, env: process.env });
      this.client = new Client({ name: "gmail-mcp-http", version: "1.0.0" });
      debugLog("Connecting MCP client");
      await this.client.connect(this.transport);
      debugLog("Listing MCP tools");
      const { tools } = await this.client.listTools();
      this.tools = tools || [];
      debugLog("MCP tools loaded", { count: this.tools.length });
    })();

    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  async listTools() {
    await this.connect();
    debugLog("Returning cached tool list", { count: this.tools?.length || 0 });
    return this.tools || [];
  }

  async callTool(name, args) {
    await this.connect();
    debugLog("Calling MCP tool", { name, args });
    return this.client.callTool({ name, arguments: args });
  }

  async close() {
    if (this.transport) {
      await this.transport.close();
    }
  }
}

function getRequesterIp(req) {
  const explicitIp = req.headers["x-user-ip"] || req.body?.requesterIp;
  if (typeof explicitIp === "string" && explicitIp.trim()) {
    return explicitIp.trim();
  }
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    const forwardedIps = forwarded.split(",").map((ip) => ip.trim());
    if (forwardedIps[0]) return forwardedIps[0];
  }
  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.trim()) {
    return realIp.trim();
  }
  return req.socket?.remoteAddress || req.ip || "unknown";
}

function getAuthenticatedUser(req) {
  const headerUser = req.headers["x-authenticated-user"] || req.headers["x-user-identity"];
  if (typeof headerUser === "string" && headerUser.trim()) {
    return headerUser.trim();
  }
  if (typeof req.body?.authenticatedUser === "string" && req.body.authenticatedUser.trim()) {
    return req.body.authenticatedUser.trim();
  }
  return "unknown";
}

function collectOpaHeaders(req) {
  const allowedHeaders = new Set([
    "authorization",
    "user-agent",
    "x-entra-token",
    "x-authenticated-user",
    "x-user-identity",
    "x-user-ip",
    "x-forwarded-for",
    "x-real-ip"
  ]);
  const headers = {};
  for (const [key, value] of Object.entries(req.headers || {})) {
    const normalizedKey = String(key).toLowerCase();
    if (allowedHeaders.has(normalizedKey) || normalizedKey.startsWith("x-")) {
      headers[normalizedKey] = value;
    }
  }
  return headers;
}

function getCorrelationId(req) {
  const headerId = req.headers["x-correlation-id"] || req.headers["x-request-id"];
  if (typeof headerId === "string" && headerId.trim()) {
    return headerId.trim();
  }
  return crypto.randomBytes(12).toString("hex");
}

function truncateText(value, maxLength = 500) {
  if (typeof value !== "string") return value;
  if (value.length <= maxLength) return value;
  return `${value.slice(0, maxLength)}...`;
}

function extractToolError(result) {
  if (!result || typeof result !== "object") return null;
  if (result.isError === true) {
    return {
      code: result.code || "tool_error",
      message: result.message || "Tool reported an error"
    };
  }
  const content = Array.isArray(result.content) ? result.content : [];
  for (const entry of content) {
    const text = typeof entry?.text === "string" ? entry.text.trim() : "";
    if (!text) continue;
    if (/^(error|failed)\b[:\s-]/i.test(text)) {
      return {
        code: "tool_result_error",
        message: text
      };
    }
  }
  return null;
}

function normalizeEmailAddress(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function splitTargetRecipients(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeEmailAddress(entry)).filter(Boolean);
  }
  if (typeof value !== "string") return [];
  return value
    .split(",")
    .map((entry) => normalizeEmailAddress(entry))
    .filter(Boolean);
}

function collectRecipientAddresses(args = {}) {
  const raw = [];
  const collect = (value) => {
    if (Array.isArray(value)) {
      value.forEach((entry) => collect(entry));
      return;
    }
    if (typeof value === "string") {
      raw.push(value);
    }
  };
  collect(args.to);
  collect(args.cc);
  collect(args.bcc);
  if (args.message && typeof args.message === "object") {
    collect(args.message.to);
    collect(args.message.cc);
    collect(args.message.bcc);
  }
  const deduped = new Set();
  for (const entry of raw) {
    const normalized = normalizeEmailAddress(entry);
    if (normalized.includes("@")) deduped.add(normalized);
  }
  return [...deduped];
}

function isExternalRecipient(recipient, authenticatedUser) {
  const recipientDomain = normalizeEmailAddress(recipient).split("@")[1] || "";
  const userDomain = normalizeEmailAddress(authenticatedUser).split("@")[1] || "";
  if (!recipientDomain) return false;
  if (!userDomain) return true;
  return recipientDomain !== userDomain;
}

function estimateMessageMetrics(args = {}) {
  const asBytes = (value) => {
    if (value === null || value === undefined) return 0;
    if (typeof value === "number") return Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
    if (typeof value === "string") return Buffer.byteLength(value, "utf8");
    if (typeof value === "boolean") return 1;
    if (Array.isArray(value)) return value.reduce((sum, entry) => sum + asBytes(entry), 0);
    if (typeof value === "object") return Buffer.byteLength(JSON.stringify(value), "utf8");
    return 0;
  };

  const bodyBytes = asBytes(args.body) + asBytes(args.message);
  const subject = typeof args.subject === "string" ? args.subject : args.message?.subject || "";
  const subjectBytes = asBytes(subject);

  const attachmentsRaw = Array.isArray(args.attachments)
    ? args.attachments
    : Array.isArray(args.message?.attachments)
      ? args.message.attachments
      : [];
  let attachmentBytes = 0;
  for (const attachment of attachmentsRaw) {
    const explicitSize = Number(
      attachment?.sizeBytes ?? attachment?.size_bytes ?? attachment?.size ?? attachment?.bytes
    );
    if (Number.isFinite(explicitSize) && explicitSize >= 0) {
      attachmentBytes += Math.floor(explicitSize);
      continue;
    }
    if (typeof attachment?.content === "string") {
      attachmentBytes += Buffer.byteLength(attachment.content, "utf8");
    } else if (typeof attachment?.data === "string") {
      attachmentBytes += Buffer.byteLength(attachment.data, "utf8");
    } else {
      attachmentBytes += asBytes(attachment);
    }
  }

  return {
    subject: typeof subject === "string" ? subject : "",
    totalBytes: bodyBytes + subjectBytes + attachmentBytes,
    attachmentBytes
  };
}

function computeRecipientCountersFromPolicyRows({
  rows,
  recipient,
  now = Date.now(),
  currentSubject = "",
  currentMessageBytes = 0,
  currentAttachmentBytes = 0
}) {
  const recipientNorm = normalizeEmailAddress(recipient);
  const oneHourAgo = now - 60 * 60 * 1000;
  const dayAgo = now - 24 * 60 * 60 * 1000;
  let emails24h = 0;
  let emails1h = 0;
  let aggregateDataVolume24h = 0;
  let totalAttachmentBytes24h = 0;
  const subjectSet = new Set();

  for (const row of rows || []) {
    const tsMs = Date.parse(row?.ts || "");
    if (!Number.isFinite(tsMs) || tsMs < dayAgo) continue;
    const rowRecipients = [
      ...splitTargetRecipients(row?.target_user_id),
      ...splitTargetRecipients(row?.recipient)
    ];
    const matched = rowRecipients.includes(recipientNorm);
    debugLog("UC29 row match check", {
      target_user_id: row?.target_user_id || null,
      rowRecipients,
      normalizedRecipient: recipientNorm,
      matched
    });
    if (!matched) continue;
    const messageBytes = Number.isFinite(Number(row?.message_bytes))
      ? Math.max(0, Number(row?.message_bytes))
      : 0;
    const attachmentBytes = Number.isFinite(Number(row?.attachment_bytes))
      ? Math.max(0, Number(row?.attachment_bytes))
      : 0;
    const subject = typeof row?.subject === "string" ? row.subject : "";

    emails24h += 1;
    aggregateDataVolume24h += messageBytes;
    totalAttachmentBytes24h += attachmentBytes;
    if (subject) subjectSet.add(subject.toLowerCase());
    if (tsMs >= oneHourAgo) emails1h += 1;
  }

  if (currentSubject) subjectSet.add(String(currentSubject).toLowerCase());

  return {
    emails_to_same_recipient_last_24h: emails24h,
    emails_to_same_recipient_last_1h: emails1h,
    aggregate_data_volume_to_recipient_last_24h_bytes: aggregateDataVolume24h + currentMessageBytes,
    unique_subjects_to_same_recipient_last_24h: subjectSet.size,
    total_attachment_bytes_to_recipient_last_24h: totalAttachmentBytes24h + currentAttachmentBytes
  };
}

async function buildOpaInput(req, toolName, args, options = {}) {
  const requesterIp = getRequesterIp(req);
  const authenticatedUser = getAuthenticatedUser(req);
  const headers = collectOpaHeaders(req);
  const context = {};

  if (toolName === "send_email") {
    const recipients = collectRecipientAddresses(args);
    const externalRecipients = recipients.filter((recipient) =>
      isExternalRecipient(recipient, authenticatedUser)
    );
    const [primaryRecipient] = externalRecipients;
    const currentMetrics = estimateMessageMetrics(args);
    let counters = {
      recipient: primaryRecipient || null,
      emails_to_same_recipient_last_24h: 0,
      aggregate_data_volume_to_recipient_last_24h_bytes: currentMetrics.totalBytes,
      emails_to_same_recipient_last_1h: 0,
      unique_subjects_to_same_recipient_last_24h: currentMetrics.subject ? 1 : 0,
      total_attachment_bytes_to_recipient_last_24h: currentMetrics.attachmentBytes,
      uc29_thresholds: {
        emails_last_24h: UC29_THRESHOLD_EMAILS_24H,
        emails_last_1h: UC29_THRESHOLD_EMAILS_1H
      }
    };

    if (primaryRecipient) {
      const hasOverride = Object.prototype.hasOwnProperty.call(options, "historyRowsOverride");
      const rows = hasOverride
        ? options.historyRowsOverride
        : typeof immudbLogger?.fetchRecentAllowedPolicyDecisions === "function"
          ? await immudbLogger.fetchRecentAllowedPolicyDecisions({
              authenticatedUser,
              toolName: "send_email",
              lookbackHours: 24
            })
          : [];
      debugLog("UC29 history rows fetched", {
        authenticatedUser,
        recipient: primaryRecipient,
        rowCount: rows.length
      });
      counters = {
        ...counters,
        ...computeRecipientCountersFromPolicyRows({
          rows,
          recipient: primaryRecipient,
          currentSubject: currentMetrics.subject,
          currentMessageBytes: currentMetrics.totalBytes,
          currentAttachmentBytes: currentMetrics.attachmentBytes
        })
      };
      debugLog("UC29 counters computed", {
        authenticatedUser,
        recipient: primaryRecipient,
        counters
      });
    }

    context.counters = counters;
  }

  return {
    tool: {
      name: toolName,
      arguments: args
    },
    requester: {
      ip: requesterIp,
      identity: authenticatedUser,
      token: headers["x-entra-token"] || headers.authorization || null
    },
    request: {
      method: req.method,
      path: req.path,
      headers,
      body: req.body || null
    },
    context
  };
}

function redactOpaInput(input) {
  if (!input || typeof input !== "object") return input;
  const headers = { ...(input.request?.headers || {}) };
  if (headers.authorization) headers.authorization = "[redacted]";
  if (headers["x-entra-token"]) headers["x-entra-token"] = "[redacted]";

  return {
    ...input,
    requester: {
      ...input.requester,
      token: input.requester?.token ? "[redacted]" : null
    },
    request: {
      ...input.request,
      headers
    }
  };
}

function normalizeOpaDecision(payload) {
  if (!payload) return { allow: false, reason: "missing_opa_response", raw: payload };
  if (typeof payload.result === "boolean") {
    return { allow: payload.result, reason: payload.result ? "ok" : "denied", raw: payload };
  }
  if (payload.result && typeof payload.result === "object") {
    const allow = Boolean(payload.result.allow);
    const reason = payload.result.reason || (allow ? "ok" : "denied");
    return { allow, reason, raw: payload };
  }
  return { allow: false, reason: "invalid_opa_response", raw: payload };
}

async function callOpaDecision(req, toolName, args) {
  if (!OPA_ENABLED) {
    return { allow: true, reason: "opa_disabled", raw: null };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), OPA_TIMEOUT_MS);
  const input = await buildOpaInput(req, toolName, args);
  if (DEBUG) {
    debugLog("OPA request", { url: OPA_DECISION_URL, input: redactOpaInput(input) });
  }

  try {
    const response = await fetch(OPA_DECISION_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({ input }),
      signal: controller.signal
    });

    const payload = await response.json().catch(() => null);
    if (DEBUG) {
      debugLog("OPA response", { status: response.status, payload });
    }
    if (!response.ok) {
      return {
        allow: OPA_FAIL_OPEN,
        reason: `opa_http_${response.status}`,
        raw: payload
      };
    }

    return normalizeOpaDecision(payload);
  } catch (error) {
    return {
      allow: OPA_FAIL_OPEN,
      reason: error?.name === "AbortError" ? "opa_timeout" : "opa_error",
      raw: { message: error?.message || String(error) }
    };
  } finally {
    clearTimeout(timeout);
  }
}

function deriveTarget(args = {}) {
  if (Array.isArray(args.to) && args.to.length > 0) return args.to.join(",");
  if (typeof args.to === "string") return args.to;
  if (typeof args.messageId === "string") return args.messageId;
  if (typeof args.q === "string") return args.q;
  if (typeof args.subject === "string") return args.subject;
  return "unknown";
}

const immudbLogger = new ImmuDBLogger({
  host: process.env.IMMUDB_HOST,
  port: process.env.IMMUDB_PORT ? Number(process.env.IMMUDB_PORT) : undefined,
  user: process.env.IMMUDB_USER,
  password: process.env.IMMUDB_PASSWORD,
  database: process.env.IMMUDB_DATABASE,
  mode: process.env.IMMUDB_MODE || "kv",
  enabled: process.env.IMMUDB_ENABLED !== "false"
});

const mcpClientManager = new McpClientManager();

app.get("/health", async (_req, res) => {
  debugLog("Health check requested");
  res.json({
    status: "ok",
    timestamp: new Date().toISOString()
  });
});

app.get("/tools", async (_req, res) => {
  try {
    debugLog("Tools endpoint requested");
    const tools = await mcpClientManager.listTools();
    res.json({ tools });
  } catch (error) {
    debugLog("Failed to list tools", { error: error?.message || error });
    res.status(500).json({ error: error?.message || "Failed to list tools" });
  }
});

app.post("/call-tool", async (req, res) => {
  const startedAt = Date.now();
  const correlationId = getCorrelationId(req);
  res.set("x-correlation-id", correlationId);
  let auditStatus = "failure";
  let auditSummary = "unknown";
  let auditErrorCode = null;
  let auditErrorMessage = null;
  try {
    const { name, arguments: args } = req.body || {};
    const authenticatedUser = getAuthenticatedUser(req);
    const hasEntraToken = Boolean(req.headers["x-entra-token"]);
    debugLog("Call tool request received", {
      name,
      hasArgs: Boolean(args),
      authenticatedUser,
      hasEntraToken
    });
    if (!name || !args) {
      return res.status(400).json({ error: "name and arguments are required" });
    }

    const opaDecision = await callOpaDecision(req, name, args);
    const requesterIp = getRequesterIp(req);
    const targetUserId = deriveTarget(args);

    const opaRequest = await buildOpaInput(req, name, args);
    const sendMetrics = name === "send_email" ? estimateMessageMetrics(args) : { totalBytes: 0, attachmentBytes: 0 };
    immudbLogger
      .recordPolicyDecision({
        authenticatedUser,
        requesterIp,
        toolName: name,
        targetUserId,
        recipient: opaRequest?.context?.counters?.recipient || normalizeEmailAddress(targetUserId),
        subject: args?.subject || args?.message?.subject || "",
        messageBytes: sendMetrics.totalBytes,
        attachmentBytes: sendMetrics.attachmentBytes,
        allow: opaDecision.allow,
        reason: opaDecision.reason,
        opaRequest: redactOpaInput(opaRequest),
        opaResponse: opaDecision.raw
      })
      .catch((error) => {
        console.warn("Failed to write immuDB policy log:", error?.message || error);
      });

    if (!opaDecision.allow) {
      debugLog("OPA denied request", { name, reason: opaDecision.reason });
      auditStatus = "failure";
      auditSummary = `${name} denied by policy`;
      immudbLogger
        .recordAction({
          authenticatedUser,
          requesterIp,
          targetUserId,
          action: name,
          status: auditStatus,
          durationMs: Date.now() - startedAt,
          resultSummary: auditSummary,
          errorCode: "policy_denied",
          errorMessage: opaDecision.reason,
          correlationId
        })
        .catch((error) => {
          console.warn("Failed to write immuDB log:", error?.message || error);
        });
      return res.status(403).json({
        error: "Request denied by policy",
        reason: opaDecision.reason
      });
    }

    const result = await mcpClientManager.callTool(name, args);
    debugLog("Tool call completed", { name });

    const toolError = extractToolError(result);
    if (toolError) {
      auditStatus = "failure";
      auditSummary = truncateText(toolError.message, 200);
      auditErrorCode = toolError.code;
      auditErrorMessage = truncateText(toolError.message);
    } else {
      auditStatus = "success";
      auditSummary = `${name} completed`;
      auditErrorCode = null;
      auditErrorMessage = null;
    }

    immudbLogger
      .recordAction({
        authenticatedUser,
        requesterIp,
        targetUserId,
        action: name,
        status: auditStatus,
        durationMs: Date.now() - startedAt,
        resultSummary: auditSummary,
        errorCode: auditErrorCode,
        errorMessage: auditErrorMessage,
        correlationId
      })
      .catch((error) => {
        console.warn("Failed to write immuDB log:", error?.message || error);
      });

    debugLog("Audit log scheduled", {
      action: name,
      requesterIp,
      targetUserId,
      status: auditStatus,
      correlationId
    });

    res.json({ success: true, result, correlationId });
  } catch (error) {
    auditErrorCode = error?.code || error?.name || "unknown";
    auditErrorMessage = truncateText(error?.message || String(error));
    auditSummary = "tool call failed";
    debugLog("Tool call failed", { error: error?.message || error });
    try {
      const { name, arguments: args } = req.body || {};
      const authenticatedUser = getAuthenticatedUser(req);
      const requesterIp = getRequesterIp(req);
      const targetUserId = deriveTarget(args);
      immudbLogger
        .recordAction({
          authenticatedUser,
          requesterIp,
          targetUserId,
          action: name || "unknown",
          status: auditStatus,
          durationMs: Date.now() - startedAt,
          resultSummary: auditSummary,
          errorCode: auditErrorCode,
          errorMessage: auditErrorMessage,
          correlationId
        })
        .catch((logError) => {
          console.warn("Failed to write immuDB log:", logError?.message || logError);
        });
    } catch (logError) {
      console.warn("Failed to build immuDB log payload:", logError?.message || logError);
    }
    res.status(500).json({ error: error?.message || "Tool call failed", correlationId });
  }
});

let server = null;
if (process.env.NODE_ENV !== "test") {
  server = app.listen(port, () => {
    console.log(`Gmail MCP HTTP wrapper running at http://localhost:${port}`);
    if (DEBUG) {
      console.log("[gmail-mcp-http][debug] Debug logging enabled");
    }
  });

  process.on("SIGINT", async () => {
    await mcpClientManager.close();
    server.close(() => process.exit(0));
  });
}

export {
  buildOpaInput,
  collectRecipientAddresses,
  computeRecipientCountersFromPolicyRows,
  estimateMessageMetrics,
  isExternalRecipient,
  normalizeEmailAddress,
  splitTargetRecipients
};
