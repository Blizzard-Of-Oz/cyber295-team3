import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ImmuDBLogger } from "./immudb-logger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const port = process.env.MCP_HTTP_PORT || 5001;
const DEBUG = process.env.DEBUG === "true";
const OPA_ENABLED = process.env.OPA_ENABLED !== "false";
const OPA_DECISION_URL =
  process.env.OPA_DECISION_URL || "http://localhost:8181/v1/data/gmail/decision";
const OPA_TIMEOUT_MS = process.env.OPA_TIMEOUT_MS ? Number(process.env.OPA_TIMEOUT_MS) : 2000;
const OPA_FAIL_OPEN = process.env.OPA_FAIL_OPEN === "true";
const URGENCY_PATTERNS = [
  { keyword: "URGENT", regex: /\burgent\b/i, score: 3 },
  { keyword: "IMMEDIATELY", regex: /\bimmediately\b/i, score: 2 },
  { keyword: "DO NOT DELAY", regex: /\bdo not delay\b/i, score: 2 },
  { keyword: "CEO DEMANDS", regex: /\bceo demands?\b/i, score: 2 },
  { keyword: "NOW", regex: /\bnow\b/i, score: 1 }
];
const URL_REGEX = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const BASE64ISH_REGEX = /^(?:[A-Za-z0-9+/_-]{12,}={0,2})$/;
const LONG_QUERY_STRING_THRESHOLD = 80;
const SUSPICIOUS_QUERY_VALUE_LENGTH = 24;
const HIGH_ENTROPY_SUBDOMAIN_THRESHOLD = 3.3;
const HIGH_ENTROPY_SUBDOMAIN_LENGTH = 12;
const SUSPICIOUS_DOMAIN_KEYWORDS = [
  "exfil",
  "c2",
  "command-and-control",
  "beacon",
  "payload",
  "tunnel",
  "dns",
  "covert",
  "steal",
  "drop",
  "collector"
];

function debugLog(message, meta) {
  if (!DEBUG) return;
  if (meta !== undefined) {
    console.log(`[gmail-mcp-http][debug] ${message}`, meta);
  } else {
    console.log(`[gmail-mcp-http][debug] ${message}`);
  }
}

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

function normalizeRecipients(value) {
  if (Array.isArray(value)) {
    return value.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim());
  }
  if (typeof value === "string" && value.trim()) {
    return [value.trim()];
  }
  return [];
}

function getContentText(args = {}, providedContext = {}) {
  if (typeof providedContext.content_text === "string" && providedContext.content_text.trim()) {
    return providedContext.content_text;
  }
  const subject = typeof args.subject === "string" ? args.subject : "";
  const body = typeof args.body === "string" ? args.body : "";
  const combined = [subject, body].filter(Boolean).join("\n");
  return combined ? `${combined}\n` : "";
}

function detectUrgencySignals(parts) {
  const haystack = parts.filter((part) => typeof part === "string" && part.trim()).join("\n");
  const matchedKeywords = [];
  let urgencyScore = 0;

  for (const pattern of URGENCY_PATTERNS) {
    if (pattern.regex.test(haystack)) {
      matchedKeywords.push(pattern.keyword);
      urgencyScore += pattern.score;
    }
  }

  return {
    urgencyManipulation: matchedKeywords.length > 0,
    urgencySignals: {
      matched_keywords: matchedKeywords,
      urgency_score: urgencyScore
    }
  };
}

function extractUrlsFromText(...parts) {
  const urls = [];
  const seen = new Set();

  for (const part of parts) {
    if (typeof part !== "string" || !part.trim()) continue;
    for (const match of part.matchAll(URL_REGEX)) {
      const url = match[0];
      if (seen.has(url)) continue;
      seen.add(url);
      urls.push(url);
    }
  }

  return urls;
}

function sanitizeHostnamePart(part) {
  if (typeof part !== "string") return "";
  return part.trim().replace(/^\.+|\.+$/g, "");
}

function shannonEntropy(value) {
  if (typeof value !== "string" || value.length === 0) return 0;
  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return Number(entropy.toFixed(3));
}

function looksBase64ish(value, minLength = SUSPICIOUS_QUERY_VALUE_LENGTH) {
  if (typeof value !== "string") return false;
  const normalized = value.trim();
  if (normalized.length < minLength) return false;
  return BASE64ISH_REGEX.test(normalized);
}

function collectSuspiciousKeywords(...parts) {
  const haystack = parts
    .filter((part) => typeof part === "string" && part.trim())
    .map((part) => part.toLowerCase())
    .join("\n");

  return SUSPICIOUS_DOMAIN_KEYWORDS.filter((keyword) => haystack.includes(keyword));
}

function analyzeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const hostname = sanitizeHostnamePart(parsed.hostname.toLowerCase());
    const hostParts = hostname.split(".").filter(Boolean);
    const domain =
      hostParts.length >= 2 ? hostParts.slice(-2).join(".") : hostname;
    const subdomain =
      hostParts.length > 2 ? hostParts.slice(0, -2).join(".") : "";
    const queryEntries = Array.from(parsed.searchParams.entries());
    const queryValues = queryEntries.map(([, value]) => value);
    const suspiciousQueryValues = queryValues.filter((value) => looksBase64ish(value));
    const queryString = parsed.search.startsWith("?") ? parsed.search.slice(1) : parsed.search;
    const subdomainEntropy = shannonEntropy(subdomain);
    const looksBase64Subdomain = looksBase64ish(subdomain, 10);
    const highEntropySubdomain =
      subdomain.length >= HIGH_ENTROPY_SUBDOMAIN_LENGTH &&
      subdomainEntropy >= HIGH_ENTROPY_SUBDOMAIN_THRESHOLD;
    const longQueryString = queryString.length >= LONG_QUERY_STRING_THRESHOLD;
    const suspiciousQueryPayload = suspiciousQueryValues.length > 0;
    const suspiciousDomainKeywords = collectSuspiciousKeywords(hostname, domain, rawUrl);
    const suspiciousDomainPattern = suspiciousDomainKeywords.length > 0;
    const suspiciousHostnamePattern = suspiciousDomainKeywords.some((keyword) => hostname.includes(keyword));

    return {
      original_url: rawUrl,
      hostname,
      domain,
      subdomain,
      query_string_length: queryString.length,
      query_param_count: queryEntries.length,
      query_param_keys: queryEntries.map(([key]) => key),
      query_values_look_base64: suspiciousQueryPayload,
      suspicious_query_value_lengths: suspiciousQueryValues.map((value) => value.length),
      subdomain_length: subdomain.length,
      subdomain_entropy: subdomainEntropy,
      suspicious_domain_keywords: suspiciousDomainKeywords,
      suspicious_domain_pattern: suspiciousDomainPattern,
      suspicious_hostname_pattern: suspiciousHostnamePattern,
      looks_base64_subdomain: looksBase64Subdomain,
      high_entropy_subdomain: highEntropySubdomain,
      long_query_string: longQueryString,
      suspicious_query_payload: suspiciousQueryPayload
    };
  } catch {
    return null;
  }
}

function analyzeUrls(parts) {
  const analyzed = extractUrlsFromText(...parts).map(analyzeUrl).filter(Boolean);
  const flagged = analyzed.filter(
    (entry) =>
      entry.looks_base64_subdomain ||
      entry.high_entropy_subdomain ||
      entry.suspicious_domain_pattern ||
      entry.suspicious_hostname_pattern ||
      entry.long_query_string ||
      entry.suspicious_query_payload
  );

  return {
    urls: analyzed,
    dnsTunnelingDetected: flagged.length > 0,
    dnsTunnelingSignals: {
      url_count: analyzed.length,
      flagged_url_count: flagged.length,
      flagged_reasons: {
        base64_subdomain_count: flagged.filter((entry) => entry.looks_base64_subdomain).length,
        high_entropy_subdomain_count: flagged.filter((entry) => entry.high_entropy_subdomain).length,
        suspicious_domain_pattern_count: flagged.filter((entry) => entry.suspicious_domain_pattern).length,
        suspicious_hostname_pattern_count: flagged.filter((entry) => entry.suspicious_hostname_pattern).length,
        long_query_string_count: flagged.filter((entry) => entry.long_query_string).length,
        suspicious_query_payload_count: flagged.filter((entry) => entry.suspicious_query_payload).length
      }
    }
  };
}

function buildPolicyContext(req, toolName, args) {
  const requestContext = req.body?.context && typeof req.body.context === "object" ? req.body.context : {};
  const recipients = [
    ...normalizeRecipients(args?.to),
    ...normalizeRecipients(args?.cc),
    ...normalizeRecipients(args?.bcc)
  ];
  const contentText = getContentText(args, requestContext);
  const userInput =
    typeof requestContext.userInput === "string"
      ? requestContext.userInput
      : typeof requestContext.user_input === "string"
        ? requestContext.user_input
        : null;

  const baseContext = {
    recipient_count:
      typeof requestContext.recipient_count === "number" ? requestContext.recipient_count : recipients.length,
    recipients: Array.isArray(requestContext.recipients) ? requestContext.recipients : recipients,
    content_text: contentText,
    user_input: userInput,
    attachment_bytes:
      typeof requestContext.attachment_bytes === "number" ? requestContext.attachment_bytes : 0,
    attachment_name:
      typeof requestContext.attachment_name === "string" ? requestContext.attachment_name : null,
    data_classification:
      typeof requestContext.data_classification === "string" ? requestContext.data_classification : "none",
    record_count: typeof requestContext.record_count === "number" ? requestContext.record_count : 0
  };

  if (toolName !== "send_email") {
    return baseContext;
  }

  const urgency = detectUrgencySignals([
    requestContext.userInput,
    requestContext.user_input,
    baseContext.user_input,
    baseContext.content_text,
    args?.subject,
    args?.body
  ]);
  const urlAnalysis = analyzeUrls([
    requestContext.userInput,
    requestContext.user_input,
    baseContext.user_input,
    baseContext.content_text,
    args?.subject,
    args?.body
  ]);

  return {
    ...baseContext,
    urgency_manipulation: urgency.urgencyManipulation,
    urgency_signals: urgency.urgencySignals,
    urls: urlAnalysis.urls,
    dns_tunneling_detected: urlAnalysis.dnsTunnelingDetected,
    dns_tunneling_signals: urlAnalysis.dnsTunnelingSignals
  };
}

function buildOpaInput(req, toolName, args) {
  const requesterIp = getRequesterIp(req);
  const authenticatedUser = getAuthenticatedUser(req);
  const headers = collectOpaHeaders(req);

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
    context: buildPolicyContext(req, toolName, args)
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
  const input = buildOpaInput(req, toolName, args);
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

function createApp({ mcpClient = mcpClientManager, logger = immudbLogger } = {}) {
  const app = express();
  app.use(express.json({ limit: "1mb" }));

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
      const tools = await mcpClient.listTools();
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

      const opaRequest = buildOpaInput(req, name, args);
      logger
        .recordPolicyDecision({
          authenticatedUser,
          requesterIp,
          toolName: name,
          targetUserId,
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
        logger
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

      const result = await mcpClient.callTool(name, args);
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

      logger
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
        logger
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

  return app;
}

let server = null;
const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectRun) {
  const app = createApp();
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
  buildPolicyContext,
  callOpaDecision,
  createApp,
  detectUrgencySignals,
  extractUrlsFromText,
  analyzeUrl,
  normalizeOpaDecision,
  redactOpaInput
};
