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
    this.debugEnabled = process.env.DEBUG === "true";
  }

  debugLog(message, meta) {
    if (!this.debugEnabled) return;
    if (meta !== undefined) {
      console.log(`[immudb-logger][debug] ${message}`, meta);
    } else {
      console.log(`[immudb-logger][debug] ${message}`);
    }
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
      await this.ensurePolicyDecisionColumns();
    } catch (error) {
      console.warn("Failed to ensure immuDB SQL table:", error.message);
    }
  }

  async ensurePolicyDecisionColumns() {
    if (!this.useSql) return;
    const addColumnStatements = [
      "ALTER TABLE mcp_policy_decisions ADD COLUMN recipient VARCHAR",
      "ALTER TABLE mcp_policy_decisions ADD COLUMN subject VARCHAR",
      "ALTER TABLE mcp_policy_decisions ADD COLUMN message_bytes INTEGER",
      "ALTER TABLE mcp_policy_decisions ADD COLUMN attachment_bytes INTEGER"
    ];
    for (const sql of addColumnStatements) {
      try {
        await this.execSqlWithRetry(sql);
      } catch (error) {
        const message = String(error?.details || error?.message || "").toLowerCase();
        if (
          message.includes("already exists") ||
          message.includes("duplicate") ||
          message.includes("exists")
        ) {
          continue;
        }
        console.warn("Failed SQL schema evolution for mcp_policy_decisions:", error.message);
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
    recipient,
    subject,
    messageBytes,
    attachmentBytes,
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
        recipient,
        subject,
        message_bytes: Number.isFinite(messageBytes) ? messageBytes : 0,
        attachment_bytes: Number.isFinite(attachmentBytes) ? attachmentBytes : 0,
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
      const normalizedMessageBytes = Number.isFinite(messageBytes) ? Math.max(0, Math.floor(messageBytes)) : 0;
      const normalizedAttachmentBytes = Number.isFinite(attachmentBytes)
        ? Math.max(0, Math.floor(attachmentBytes))
        : 0;
      const sql =
        "INSERT INTO mcp_policy_decisions(authenticated_user, requester_ip, tool_name, target_user_id, recipient, subject, message_bytes, attachment_bytes, allow, reason, opa_request, opa_response, ts) VALUES('" +
        `${esc(authenticatedUser)}','${esc(requesterIp)}','${esc(toolName)}','${esc(targetUserId)}','${esc(recipient)}','${esc(subject)}',${normalizedMessageBytes},${normalizedAttachmentBytes},'${esc(Boolean(allow))}','${esc(reason)}','${esc(JSON.stringify(opaRequest))}','${esc(JSON.stringify(opaResponse))}','${esc(timestamp)}')`;
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

  async fetchRecentAllowedPolicyDecisions({
    authenticatedUser,
    toolName,
    normalizedRecipient,
    lookbackHours = 24
  } = {}) {
    if (!this.enabled || !this.useSql) return [];
    if (!authenticatedUser || !toolName) return [];

    await this.init();
    const esc = (str) => String(str ?? "").replace(/'/g, "''");
    const cutoff = new Date(Date.now() - lookbackHours * 60 * 60 * 1000).toISOString();
    const sql =
      "SELECT authenticated_user, tool_name, target_user_id, recipient, subject, message_bytes, attachment_bytes, allow, ts, opa_request FROM mcp_policy_decisions WHERE " +
      `authenticated_user='${esc(authenticatedUser)}' AND ts >= '${esc(cutoff)}' ORDER BY id DESC LIMIT 500`;
    this.debugLog("UC29 SQL lookup params", {
      authenticatedUser,
      toolName,
      normalizedRecipient: normalizedRecipient || null,
      lookbackHours,
      cutoff
    });

    const runQuery = async () => {
      const response = await this.client.SQLQuery({ sql });
      const rows = Array.isArray(response?.rows) ? response.rows : [];
      this.debugLog("UC29 SQL raw rows returned", { rowCount: rows.length });
      return rows.map((row) => {
        const asNum = (value) => {
          const raw = value?.prop ?? value;
          const parsed = Number(raw);
          return Number.isFinite(parsed) ? parsed : 0;
        };
        const asStr = (value) => String(value?.prop ?? value ?? "");
        const normalizeEmail = (value) => asStr(value).trim().toLowerCase();
        const splitRecipients = (value) =>
          asStr(value)
            .split(",")
            .map((entry) => entry.trim().toLowerCase())
            .filter(Boolean);
        const parseRequestRecipients = (rawOpaRequest) => {
          if (!rawOpaRequest) return [];
          try {
            const payload = JSON.parse(asStr(rawOpaRequest));
            const args = payload?.tool?.arguments || {};
            const collected = [];
            const collect = (input) => {
              if (Array.isArray(input)) {
                input.forEach(collect);
                return;
              }
              if (typeof input === "string") collected.push(input);
            };
            collect(args.to);
            collect(args.cc);
            collect(args.bcc);
            collect(args?.message?.to);
            collect(args?.message?.cc);
            collect(args?.message?.bcc);
            return collected
              .map((entry) => normalizeEmail(entry))
              .filter((entry) => entry.includes("@"));
          } catch (_error) {
            return [];
          }
        };

        const targetRecipients = splitRecipients(row.target_user_id);
        const recipientColumn = splitRecipients(row.recipient);
        const fallbackRecipients = parseRequestRecipients(row.opa_request);
        const allRecipients = [...new Set([...targetRecipients, ...recipientColumn, ...fallbackRecipients])];
        const toolNameValue = normalizeEmail(row.tool_name);
        const allowValue = asStr(row.allow).trim().toLowerCase();
        const allowNormalized = allowValue === "true" || allowValue === "allow" || allowValue === "1";
        const recipientMatches = normalizedRecipient ? allRecipients.includes(normalizedRecipient) : true;
        const toolMatches = toolNameValue === String(toolName).trim().toLowerCase();

        return {
          authenticated_user: asStr(row.authenticated_user),
          tool_name: asStr(row.tool_name),
          target_user_id: asStr(row.target_user_id),
          recipient: asStr(row.recipient),
          subject: asStr(row.subject),
          message_bytes: asNum(row.message_bytes),
          attachment_bytes: asNum(row.attachment_bytes),
          allow: allowValue,
          allow_normalized: allowNormalized,
          ts: asStr(row.ts),
          all_recipients: allRecipients,
          tool_matches: toolMatches,
          recipient_matches: recipientMatches
        };
      });
    };

    try {
      const parsedRows = await runQuery();
      const matchedRows = parsedRows.filter(
        (row) => row.tool_matches && row.allow_normalized && row.recipient_matches
      );
      this.debugLog("UC29 SQL parsed rows", {
        rows: parsedRows.map((row) => ({
          target_user_id: row.target_user_id,
          tool_name: row.tool_name,
          allow: row.allow,
          ts: row.ts
        }))
      });
      this.debugLog("UC29 SQL matched rows", {
        matchedRowCount: matchedRows.length,
        rows: matchedRows.map((row) => ({
          target_user_id: row.target_user_id,
          tool_name: row.tool_name,
          allow: row.allow,
          ts: row.ts
        }))
      });
      return matchedRows;
    } catch (error) {
      if (error.code === 7 && error.details?.includes("token has expired")) {
        await this.reAuthenticate();
        return runQuery();
      }
      return [];
    }
  }
}
