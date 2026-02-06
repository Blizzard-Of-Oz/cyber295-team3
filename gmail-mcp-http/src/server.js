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

    const result = await mcpClientManager.callTool(name, args);
    debugLog("Tool call completed", { name });

    const requesterIp = getRequesterIp(req);
    const targetUserId = deriveTarget(args);

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
