import { createRequire } from "module";
import crypto from "crypto";

const require = createRequire(import.meta.url);

let ImmudbClient;
try {
  const mod = require("immudb-node");
  ImmudbClient = mod.default || mod;
  if (!ImmudbClient || typeof ImmudbClient !== "function") {
    ImmudbClient = null;
  }
} catch (error) {
  ImmudbClient = null;
}

export class ImmuDBLogger {
  constructor({ host, port, user, password, database, mode = "kv", enabled = true } = {}) {
    if (!enabled) {
      this.enabled = false;
      return;
    }

    if (!ImmudbClient) {
      console.warn("immudb-node not available; immuDB logging disabled");
      this.enabled = false;
      return;
    }

    if (!host || !port || !user || !password || !database) {
      console.warn("Missing immuDB configuration; immuDB logging disabled");
      this.enabled = false;
      return;
    }

    const normalizedMode = ["kv", "sql", "both"].includes(mode) ? mode : "kv";
    this.useKv = normalizedMode === "kv" || normalizedMode === "both";
    this.useSql = normalizedMode === "sql" || normalizedMode === "both";

    this.enabled = true;
    this.host = host;
    this.port = port;
    this.user = user;
    this.password = password;
    this.database = database;
    this.client = null;
    this.ready = null;
  }

  async init() {
    if (!this.enabled) return;
    if (!this.ready) {
      this.ready = (async () => {
        this.client = new ImmudbClient({
          host: this.host,
          port: this.port,
          rootPath: "/tmp/immudb-node-state"
        });

        await this.client.login({ user: this.user, password: this.password });
        await this.client.useDatabase({ databasename: this.database });

        if (this.useSql) {
          await this.ensureSqlArtifacts();
        }
      })();
    }

    return this.ready;
  }

  async ensureSqlArtifacts() {
    const ddlActions =
      "CREATE TABLE IF NOT EXISTS mcp_actions(" +
      "id INTEGER AUTO_INCREMENT," +
      "authenticated_user VARCHAR," +
      "requester_ip VARCHAR," +
      "target_user_id VARCHAR," +
      "action VARCHAR," +
      "ts VARCHAR," +
      "PRIMARY KEY (id))";

    const ddlPolicy =
      "CREATE TABLE IF NOT EXISTS mcp_policy_decisions(" +
      "id INTEGER AUTO_INCREMENT," +
      "authenticated_user VARCHAR," +
      "requester_ip VARCHAR," +
      "tool_name VARCHAR," +
      "target_user_id VARCHAR," +
      "allow VARCHAR," +
      "reason VARCHAR," +
      "opa_request VARCHAR," +
      "opa_response VARCHAR," +
      "ts VARCHAR," +
      "PRIMARY KEY (id))";

    try {
      await this.execSqlWithRetry(ddlActions);
      await this.execSqlWithRetry(ddlPolicy);
    } catch (error) {
      console.warn("Failed to ensure immuDB SQL table:", error.message);
    }
  }

  async reAuthenticate() {
    if (!this.client) return;
    await this.client.login({ user: this.user, password: this.password });
    await this.client.useDatabase({ databasename: this.database });
  }

  async execSqlWithRetry(sql, attempts = 3) {
    let lastError;
    for (let i = 0; i < attempts; i += 1) {
      try {
        await this.client.SQLExec({ sql });
        return;
      } catch (error) {
        lastError = error;
        const message = error?.details || error?.message || "";
        if (!message.includes("tx read conflict")) {
          throw error;
        }
        const delayMs = 50 * (i + 1);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }

    if (lastError) {
      throw lastError;
    }
  }

  async recordAction({ authenticatedUser, requesterIp, targetUserId, action }) {
    if (!this.enabled) return;
    if (!requesterIp || !action) return;

    await this.init();
    const timestamp = new Date().toISOString();

    const kvWrite = async () => {
      if (!this.useKv) return;
      const key = `mcp-action:${Date.now()}:${crypto.randomBytes(6).toString("hex")}`;
      const value = JSON.stringify({ authenticatedUser, requesterIp, targetUserId, action, timestamp });
      await this.client.set({ key, value });
    };

    const sqlInsert = async () => {
      if (!this.useSql) return;
      const esc = (str) => String(str ?? "unknown").replace(/'/g, "''");
      const sql =
        "INSERT INTO mcp_actions(authenticated_user, requester_ip, target_user_id, action, ts) VALUES('" +
        `${esc(authenticatedUser)}','${esc(requesterIp)}','${esc(targetUserId)}','${esc(action)}','${esc(timestamp)}')`;
      await this.execSqlWithRetry(sql);
    };

    const executeWithRetry = async (fn) => {
      try {
        await fn();
      } catch (error) {
        if (error.code === 7 && error.details?.includes("token has expired")) {
          await this.reAuthenticate();
          await fn();
        }
      }
    };

    await Promise.allSettled([executeWithRetry(kvWrite), executeWithRetry(sqlInsert)]);
  }

  async recordPolicyDecision({
    authenticatedUser,
    requesterIp,
    toolName,
    targetUserId,
    allow,
    reason,
    opaRequest,
    opaResponse
  }) {
    if (!this.enabled) return;
    if (!requesterIp || !toolName) return;

    await this.init();
    const timestamp = new Date().toISOString();

    const kvWrite = async () => {
      if (!this.useKv) return;
      const key = `mcp-policy:${Date.now()}:${crypto.randomBytes(6).toString("hex")}`;
      const value = JSON.stringify({
        authenticatedUser,
        requesterIp,
        toolName,
        targetUserId,
        allow: Boolean(allow),
        reason: reason || "unknown",
        opaRequest,
        opaResponse,
        timestamp
      });
      await this.client.set({ key, value });
    };

    const sqlInsert = async () => {
      if (!this.useSql) return;
      const esc = (str) => String(str ?? "unknown").replace(/'/g, "''");
      const sql =
        "INSERT INTO mcp_policy_decisions(authenticated_user, requester_ip, tool_name, target_user_id, allow, reason, opa_request, opa_response, ts) VALUES('" +
        `${esc(authenticatedUser)}','${esc(requesterIp)}','${esc(toolName)}','${esc(targetUserId)}','${esc(Boolean(allow))}','${esc(reason)}','${esc(JSON.stringify(opaRequest))}','${esc(JSON.stringify(opaResponse))}','${esc(timestamp)}')`;
      await this.execSqlWithRetry(sql);
    };

    const executeWithRetry = async (fn) => {
      try {
        await fn();
      } catch (error) {
        if (error.code === 7 && error.details?.includes("token has expired")) {
          await this.reAuthenticate();
          await fn();
        }
      }
    };

    await Promise.allSettled([executeWithRetry(kvWrite), executeWithRetry(sqlInsert)]);
  }
}
