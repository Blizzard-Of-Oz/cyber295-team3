import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
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
    }
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
    immudbLogger
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
      return res.status(403).json({
        error: "Request denied by policy",
        reason: opaDecision.reason
      });
    }

    const result = await mcpClientManager.callTool(name, args);
    debugLog("Tool call completed", { name });

    immudbLogger
      .recordAction({
        authenticatedUser,
        requesterIp,
        targetUserId,
        action: name
      })
      .catch((error) => {
        console.warn("Failed to write immuDB log:", error?.message || error);
      });

    debugLog("Audit log scheduled", {
      action: name,
      requesterIp,
      targetUserId
    });

    res.json({ success: true, result });
  } catch (error) {
    debugLog("Tool call failed", { error: error?.message || error });
    res.status(500).json({ error: error?.message || "Tool call failed" });
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
  server.close(() => process.exit(0));
});
