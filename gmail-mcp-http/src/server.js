import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import fs from "fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ImmuDBLogger } from "./immudb-logger.js";
import { createDemoRouter } from "./demo.js";
import { DemoRequestIdGenerator, AccountLockManager } from "./demo-utils.js";
import { RateLimiter, parseRateLimitConfig } from "./rate-limiter.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.MCP_HTTP_PORT || 5001;
const DEBUG = process.env.DEBUG === "true";
const OPA_ENABLED = process.env.OPA_ENABLED !== "false";
const OPA_DECISION_URL =
  process.env.OPA_DECISION_URL || "http://localhost:8181/v1/data/gmail/decision";
const OPA_TIMEOUT_MS = process.env.OPA_TIMEOUT_MS ? Number(process.env.OPA_TIMEOUT_MS) : 2000;
const OPA_FAIL_OPEN = process.env.OPA_FAIL_OPEN === "true";
const ENABLE_DEMO_ROUTES = process.env.ENABLE_DEMO_ROUTES !== "false";

// Demo utilities (loaded only if demo routes are enabled)
let demoRequestIdGenerator = null;
let accountLockManager = null;

if (ENABLE_DEMO_ROUTES) {
  demoRequestIdGenerator = new DemoRequestIdGenerator();
  accountLockManager = new AccountLockManager();
}

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

function normalizeEmailList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.filter((v) => typeof v === "string" && v.includes("@"));
  if (typeof value === "string") {
    return value
      .split(/[\s,;]+/)
      .map((v) => v.trim())
      .filter((v) => v.includes("@"));
  }
  return [];
}

function unique(array) {
  return [...new Set(array)];
}

function normalizeAttachmentPaths(args) {
  const raw = [];

  if (Array.isArray(args?.attachments)) {
    raw.push(...args.attachments);
  }

  if (typeof args?.attachmentPath === "string") {
    raw.push(args.attachmentPath);
  }

  if (typeof args?.attachment_path === "string") {
    raw.push(args.attachment_path);
  }

  return raw
    .map((value) => (typeof value === "string" ? value.trim() : ""))
    .filter(Boolean);
}

function deriveAttachmentMetadata(args) {
  const explicitBytes = Number(args?.attachmentBytes || args?.attachment_bytes || 0);
  const explicitName = args?.attachmentName || args?.attachment_name || null;
  const paths = normalizeAttachmentPaths(args);

  if (paths.length === 0) {
    return {
      attachmentBytes: explicitBytes,
      attachmentName: explicitName,
      attachmentCount: 0
    };
  }

  let totalBytes = 0;
  const names = [];

  for (const filePath of paths) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.isFile()) {
        totalBytes += stat.size;
        names.push(path.basename(filePath));
      }
    } catch (_error) {
      // Ignore inaccessible attachment paths; Gmail tool will return explicit send errors.
    }
  }

  const mergedBytes = explicitBytes > 0 ? explicitBytes : totalBytes;
  const mergedName = explicitName || (names.length > 0 ? names.join(",") : null);

  return {
    attachmentBytes: mergedBytes,
    attachmentName: mergedName,
    attachmentCount: paths.length
  };
}

function normalizeToolArguments(name, args) {
  const normalized = args && typeof args === "object" ? { ...args } : {};
  if (name === "send_email" || name === "draft_email") {
    const attachments = normalizeAttachmentPaths(normalized);
    if (attachments.length > 0) {
      normalized.attachments = unique(attachments);
    }
  }
  return normalized;
}

// NOTE: Urgency score calculation is now handled by OPA policy, not by this application.
// OPA uses urgency_keywords from data.json and checks both content_text and user_input.

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

function buildOpaInput(req, toolName, args) {
  const requesterIp = getRequesterIp(req);
  const authenticatedUser = getAuthenticatedUser(req);
  const headers = collectOpaHeaders(req);

  const recipients = unique([
    ...normalizeEmailList(args?.to),
    ...normalizeEmailList(args?.cc),
    ...normalizeEmailList(args?.bcc),
    ...normalizeEmailList(args?.message?.to)
  ]);
  const contentText = `${args?.subject || ""}\n${args?.body || ""}\n${args?.message?.body || ""}`;
  const userInput = req.body?.context?.userInput || null;

  const attachmentMeta = deriveAttachmentMetadata(args);

  const opaInput = {
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
    context: {
      recipient_count: recipients.length,
      recipients,
      content_text: contentText,
      user_input: userInput,
      attachment_bytes: Number(attachmentMeta.attachmentBytes || 0),
      attachment_name: attachmentMeta.attachmentName,
      attachment_count: attachmentMeta.attachmentCount,
      data_classification: args?.dataClassification || args?.data_classification || "none",
      record_count: Number(args?.recordCount || args?.record_count || 0)
    }
  };

  // For demo/testing purposes only: allow explicit timestamp in nanoseconds
  // Only accepted when ENABLE_DEMO_ROUTES is true to prevent production misuse
  // In production (ENABLE_DEMO_ROUTES=false), OPA always uses its own server time which is secure
  if (ENABLE_DEMO_ROUTES && req.headers["x-demo-timestamp-ns"]) {
    const timestampNs = Number(req.headers["x-demo-timestamp-ns"]);
    if (!isNaN(timestampNs) && timestampNs > 0) {
      opaInput.timestamp = timestampNs;
    }
  }

  return opaInput;
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
    return {
      allow,
      reason,
      decision: payload.result.decision || (allow ? "ALLOW" : "DENY"),
      reasons: payload.result.reasons || [reason],
      actions: payload.result.actions || [],
      cooldown_seconds: payload.result.cooldown_seconds || 0,
      risk: payload.result.risk || "medium",
      policy_version: payload.result.policy_version || "v1",
      triggered_controls: payload.result.triggered_controls || [],
      raw: payload
    };
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

const rateLimiter = new RateLimiter(parseRateLimitConfig(process.env));

// Log rate limiter configuration for debugging
if (DEBUG) {
  console.log("[Server] Rate Limiter Configuration:", {
    enabled: rateLimiter.enabled,
    redisHost: rateLimiter.redisHost,
    redisPort: rateLimiter.redisPort,
    redisUsername: rateLimiter.redisUsername ? "****" : undefined,
    redisPassword: rateLimiter.redisPassword ? "****" : undefined,
    limits: rateLimiter.limits,
    defaultLimits: rateLimiter.defaultLimits
  });
}

const mcpClientManager = new McpClientManager();

// Mount demo routes if enabled (default: enabled in dev environments)
if (ENABLE_DEMO_ROUTES && accountLockManager) {
  const demoRouter = createDemoRouter(port, accountLockManager);
  app.use(demoRouter);
}

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

// Rate limit status endpoint (for debugging/monitoring)
app.get("/rate-limit/status", async (req, res) => {
  try {
    const scope = req.query.scope || "identity";
    const value = req.query.value || getAuthenticatedUser(req);
    const action = req.query.action;

    if (!action) {
      return res.status(400).json({ error: "action query parameter is required" });
    }

    const status = await rateLimiter.getStatus(scope, value, action);
    res.json(status);
  } catch (error) {
    debugLog("Failed to get rate limit status", { error: error?.message || error });
    res.status(500).json({ error: error?.message || "Failed to get rate limit status" });
  }
});

// Reset rate limit endpoint (for testing/admin purposes)
// Only available when ENABLE_DEMO_ROUTES is true
if (ENABLE_DEMO_ROUTES) {
  app.post("/rate-limit/reset", async (req, res) => {
    try {
      const { scope, value, action } = req.body || {};

      if (!scope || !value || !action) {
        return res.status(400).json({ error: "scope, value, and action are required in request body" });
      }

      await rateLimiter.resetLimit(scope, value, action);
      res.json({ success: true, message: `Rate limit reset for ${scope}:${value}:${action}` });
    } catch (error) {
      debugLog("Failed to reset rate limit", { error: error?.message || error });
      res.status(500).json({ error: error?.message || "Failed to reset rate limit" });
    }
  });

  // Debug endpoint - check Redis connection and rate limit keys
  app.get("/rate-limit/debug", async (req, res) => {
    try {
      const debugInfo = {
        rateLimiterEnabled: rateLimiter.enabled,
        redisConnected: rateLimiter.client?.isOpen,
        redisHost: rateLimiter.redisHost,
        redisPort: rateLimiter.redisPort,
        limits: rateLimiter.limits,
        defaultLimits: rateLimiter.defaultLimits
      };

      // Try to connect if not already connected
      if (!rateLimiter.client?.isOpen) {
        try {
          await rateLimiter.connect();
          debugInfo.redisConnected = rateLimiter.client?.isOpen;
        } catch (err) {
          debugInfo.connectionError = err.message;
        }
      }

      // Try to get keys from Redis
      if (rateLimiter.client?.isOpen) {
        try {
          const keys = await rateLimiter.client.keys("ratelimit:*");
          debugInfo.rateLimitKeys = {
            total: keys.length,
            sample: keys.slice(0, 10),
            allKeys: keys
          };

          // Get values for sample keys
          if (keys.length > 0) {
            const sampleKeys = keys.slice(0, 5);
            debugInfo.sampleKeyValues = {};
            for (const key of sampleKeys) {
              const value = await rateLimiter.client.get(key);
              const ttl = await rateLimiter.client.ttl(key);
              debugInfo.sampleKeyValues[key] = { value, ttl };
            }
          }
        } catch (err) {
          debugInfo.keyQueryError = err.message;
        }
      }

      res.json(debugInfo);
    } catch (error) {
      debugLog("Failed to get rate limit debug info", { error: error?.message || error });
      res.status(500).json({ error: error?.message || "Failed to get debug info" });
    }
  });
}

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
    const normalizedArgs = normalizeToolArguments(name, args);
    const authenticatedUser = getAuthenticatedUser(req);
    if (accountLockManager && accountLockManager.isLocked(authenticatedUser)) {
      return res.status(403).json({ error: "Request denied by policy", reason: "account locked" });
    }
    const hasEntraToken = Boolean(req.headers["x-entra-token"]);
    debugLog("Call tool request received", {
      name,
      hasArgs: Boolean(normalizedArgs),
      authenticatedUser,
      hasEntraToken
    });
    if (!name || !normalizedArgs) {
      return res.status(400).json({ error: "name and arguments are required" });
    }

    // Check rate limit across multiple scopes
    const ip = getRequesterIp(req);
    const userAgent = req.headers["user-agent"] || "unknown";
    
    const rateLimitChecks = [
      { scope: "identity", value: authenticatedUser },
      { scope: "ip", value: ip },
      { scope: "useragent", value: userAgent }
    ];
    
    const rateLimitResult = await rateLimiter.checkMultiple(rateLimitChecks, name);
    
    // Set headers from the most restrictive limit (the one that was violated or has least remaining)
    const mostRestrictive = rateLimitResult.results
      .filter(r => r.limit) // Only consider configured limits
      .sort((a, b) => {
        // Prioritize violated limits
        if (a.allowed !== b.allowed) return a.allowed ? 1 : -1;
        // Then by remaining count
        return (a.remaining || 0) - (b.remaining || 0);
      })[0];
    
    if (mostRestrictive && mostRestrictive.limit) {
      res.set("x-ratelimit-limit", mostRestrictive.limit);
      res.set("x-ratelimit-remaining", mostRestrictive.remaining || 0);
      res.set("x-ratelimit-window", mostRestrictive.window);
      res.set("x-ratelimit-scope", mostRestrictive.scope);
      if (mostRestrictive.resetIn) {
        res.set("x-ratelimit-reset", mostRestrictive.resetIn);
      }
    }
    
    if (!rateLimitResult.allowed) {
      const violated = rateLimitResult.violated;
      debugLog("Rate limit exceeded", { 
        name, 
        authenticatedUser, 
        scope: violated.scope,
        reason: violated.reason 
      });
      return res.status(429).json({
        error: "Rate limit exceeded",
        scope: violated.scope,
        reason: violated.reason,
        limit: violated.limit,
        window: violated.window,
        resetIn: violated.resetIn,
        message: `Rate limit exceeded for scope '${violated.scope}'. Limit: ${violated.limit} requests per ${violated.window} seconds. Try again in ${violated.resetIn} seconds.`
      });
    }

    const opaDecision = await callOpaDecision(req, name, normalizedArgs);
    const requesterIp = getRequesterIp(req);
    const targetUserId = deriveTarget(normalizedArgs);

    const opaRequest = buildOpaInput(req, name, normalizedArgs);
    const requestId = req.body?.request_id || (demoRequestIdGenerator ? demoRequestIdGenerator.nextId() : `Request-${crypto.randomBytes(6).toString("hex")}`);
    immudbLogger
      .recordPolicyDecision({
        requestId,
        authenticatedUser,
        requesterIp,
        toolName: name,
        targetUserId,
        allow: opaDecision.allow,
        reason: opaDecision.reason,
        decision: opaDecision.decision,
        reasons: opaDecision.reasons,
        policyVersion: opaDecision.policy_version,
        triggeredControls: opaDecision.triggered_controls,
        opaRequest: redactOpaInput(opaRequest),
        opaResponse: opaDecision.raw
      })
      .catch((error) => {
        console.warn("Failed to write immuDB policy log:", error?.message || error);
      });

    if (Array.isArray(opaDecision.actions) && opaDecision.actions.includes("ALERT_SECURITY")) {
      immudbLogger.recordAlert({
        requestId,
        authenticatedUser,
        requesterIp,
        toolName: name,
        reason: opaDecision.reason,
        reasons: opaDecision.reasons,
        actions: opaDecision.actions,
        risk: opaDecision.risk
      });
    }

    if (Array.isArray(opaDecision.actions) && opaDecision.actions.includes("LOCK_ACCOUNT")) {
      if (accountLockManager) {
        accountLockManager.lockAccount(authenticatedUser, { requestId, reason: opaDecision.reason });
      }
    }

    if (opaDecision.decision === "THROTTLE") {
      return res.status(429).json({
        error: "Request throttled by policy",
        reason: opaDecision.reason,
        cooldown_seconds: opaDecision.cooldown_seconds,
        message: `cooling-off period ${opaDecision.cooldown_seconds}s, confirm out-of-band`,
        request_id: requestId
      });
    }

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
        reason: opaDecision.reason,
        reasons: opaDecision.reasons,
        request_id: requestId
      });
    }

    const result = await mcpClientManager.callTool(name, normalizedArgs);
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

    res.json({ success: true, result, correlationId, request_id: requestId });
  } catch (error) {
    auditErrorCode = error?.code || error?.name || "unknown";
    auditErrorMessage = truncateText(error?.message || String(error));
    auditSummary = "tool call failed";
    debugLog("Tool call failed", { error: error?.message || error });
    try {
      const { name, arguments: args } = req.body || {};
      const normalizedArgs = normalizeToolArguments(name, args);
      const authenticatedUser = getAuthenticatedUser(req);
      const requesterIp = getRequesterIp(req);
      const targetUserId = deriveTarget(normalizedArgs);
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



const server = app.listen(port, () => {
  console.log(`Gmail MCP HTTP wrapper running at http://localhost:${port}`);
  if (DEBUG) {
    console.log("[gmail-mcp-http][debug] Debug logging enabled");
  }
});

process.on("SIGINT", async () => {
  await mcpClientManager.close();
  await rateLimiter.close();
  server.close(() => process.exit(0));
});
