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
    this.sqlQueue = Promise.resolve();
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
      "status VARCHAR," +
      "duration_ms INTEGER," +
      "result_summary VARCHAR," +
      "error_code VARCHAR," +
      "error_message VARCHAR," +
      "correlation_id VARCHAR," +
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
      await this.ensureActionColumns();
    } catch (error) {
      console.warn("Failed to ensure immuDB SQL table:", error.message);
    }
  }

  async ensureActionColumns() {
    if (!this.useSql) return;

    const columns = [
      ["status", "VARCHAR"],
      ["duration_ms", "INTEGER"],
      ["result_summary", "VARCHAR"],
      ["error_code", "VARCHAR"],
      ["error_message", "VARCHAR"],
      ["correlation_id", "VARCHAR"]
    ];

    for (const [name, type] of columns) {
      try {
        await this.execSqlWithRetry(`ALTER TABLE mcp_actions ADD COLUMN ${name} ${type}`);
      } catch (error) {
        const message = (error?.details || error?.message || "").toLowerCase();
        if (!message.includes("exist") && !message.includes("duplicate") && !message.includes("already")) {
          console.warn(`Failed to add mcp_actions column ${name}:`, error?.message || error);
        }
      }
    }
  }

  async reAuthenticate() {
    if (!this.client) return;
    await this.client.login({ user: this.user, password: this.password });
    await this.client.useDatabase({ databasename: this.database });
  }

  enqueueSql(task) {
    const run = this.sqlQueue.then(task, task);
    this.sqlQueue = run.catch(() => {});
    return run;
  }

  async execSqlWithRetry(sql, attempts = 3) {
    return this.enqueueSql(async () => {
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
          const delayMs = 75 * (i + 1) + Math.floor(Math.random() * 50);
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
      }

      if (lastError) {
        throw lastError;
      }
    });
  }

  async recordAction({
    authenticatedUser,
    requesterIp,
    targetUserId,
    action,
    status,
    durationMs,
    resultSummary,
    errorCode,
    errorMessage,
    correlationId
  }) {
    if (!this.enabled) return;
    if (!requesterIp || !action) return;

    await this.init();
    const timestamp = new Date().toISOString();

    const kvWrite = async () => {
      if (!this.useKv) return;
      const key = `mcp-action:${Date.now()}:${crypto.randomBytes(6).toString("hex")}`;
      const value = JSON.stringify({
        authenticatedUser,
        requesterIp,
        targetUserId,
        action,
        status,
        duration_ms: durationMs,
        result_summary: resultSummary,
        error_code: errorCode,
        error_message: errorMessage,
        correlation_id: correlationId,
        timestamp
      });
      await this.client.set({ key, value });
    };

    const sqlInsert = async () => {
      if (!this.useSql) return;
      const esc = (str) => String(str ?? "unknown").replace(/'/g, "''");
      const durationValue = Number.isFinite(durationMs) ? durationMs : null;
      const sql =
        "INSERT INTO mcp_actions(authenticated_user, requester_ip, target_user_id, action, status, duration_ms, result_summary, error_code, error_message, correlation_id, ts) VALUES('" +
        `${esc(authenticatedUser)}','${esc(requesterIp)}','${esc(targetUserId)}','${esc(action)}','${esc(status)}',${durationValue === null ? "null" : durationValue},'${esc(resultSummary)}','${esc(errorCode)}','${esc(errorMessage)}','${esc(correlationId)}','${esc(timestamp)}')`;
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
