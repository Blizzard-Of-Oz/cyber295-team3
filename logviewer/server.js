import express from "express";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

dotenv.config();

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.LOGVIEWER_PORT || 5002;

let ImmudbClient;
try {
  const mod = require("immudb-node");
  ImmudbClient = mod.default || mod;
} catch (error) {
  console.error("immudb-node not available:", error.message);
  ImmudbClient = null;
}

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let immudbClient = null;
let immudbConnecting = false;
let reconnectTimer = null;
let reconnectDelayMs = 1000;
const RECONNECT_MAX_DELAY_MS = 30000;

async function initImmuDB() {
  if (!ImmudbClient) {
    console.error("immudb-node not loaded");
    return null;
  }

  try {
    const host = process.env.IMMUDB_HOST;
    const port = parseInt(process.env.IMMUDB_PORT, 10);
    const user = process.env.IMMUDB_USER;
    const password = process.env.IMMUDB_PASSWORD;
    const database = process.env.IMMUDB_DATABASE;

    if (!host || !port || !user || !password || !database) {
      console.error("Missing immuDB configuration");
      return null;
    }

    const client = new ImmudbClient({
      host,
      port,
      rootPath: "/tmp/immudb-logviewer-state"
    });

    await client.login({ user, password });
    await client.useDatabase({ databasename: database });

    console.log(`Connected to immuDB: ${host}:${port}/${database}`);
    return client;
  } catch (error) {
    console.error("Failed to connect to immuDB:", error.message);
    return null;
  }
}

async function reAuthenticateImmuDB() {
  if (!immudbClient) {
    console.log("No client to re-authenticate, initializing new connection...");
    immudbClient = null;
    return connectImmuDBWithRetry();
  }

  try {
    const user = process.env.IMMUDB_USER;
    const password = process.env.IMMUDB_PASSWORD;
    const database = process.env.IMMUDB_DATABASE;

    console.log("Re-authenticating with immuDB...");
    await immudbClient.login({ user, password });
    await immudbClient.useDatabase({ databasename: database });
    console.log("Re-authentication successful");
    return immudbClient;
  } catch (error) {
    console.error("Re-authentication failed:", error.message);
    immudbClient = null;
    return connectImmuDBWithRetry();
  }
}

async function connectImmuDBWithRetry() {
  if (immudbConnecting || immudbClient) {
    return immudbClient;
  }

  immudbConnecting = true;
  const client = await initImmuDB();
  immudbConnecting = false;

  if (client) {
    immudbClient = client;
    reconnectDelayMs = 1000;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    return immudbClient;
  }

  if (!reconnectTimer) {
    const delay = reconnectDelayMs;
    reconnectDelayMs = Math.min(reconnectDelayMs * 2, RECONNECT_MAX_DELAY_MS);
    console.warn(`immuDB not ready. Retrying in ${delay}ms...`);
    reconnectTimer = setTimeout(async () => {
      reconnectTimer = null;
      await connectImmuDBWithRetry();
    }, delay);
  }

  return null;
}

app.get("/api/tables", async (_req, res) => {
  try {
    if (!immudbClient) {
      await connectImmuDBWithRetry();
    }
    if (!immudbClient) {
      return res.status(503).json({ error: "immuDB not connected" });
    }

    try {
      const tables = await immudbClient.SQLListTables();
      const tableNames = (tables || []).map((table) => table?.name || table).filter(Boolean);
      res.json({ tables: tableNames });
    } catch (error) {
      if (error.code === 7 && error.details?.includes("token has expired")) {
        console.log("Token expired, re-authenticating...");
        await reAuthenticateImmuDB();
        const tables = await immudbClient.SQLListTables();
        const tableNames = (tables || []).map((table) => table?.name || table).filter(Boolean);
        res.json({ tables: tableNames });
      } else {
        throw error;
      }
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function isSafeSqlIdentifier(value) {
  return typeof value === "string" && /^[A-Za-z0-9_]+$/.test(value);
}

async function fetchKvLogs(prefix) {
  const logs = [];
  const kvResult = await immudbClient.scan({
    prefix,
    limit: 100,
    desc: true
  });

  if (kvResult?.entriesList && kvResult.entriesList.length > 0) {
    kvResult.entriesList.forEach((entry) => {
      try {
        const key = entry.key.toString();
        const value = JSON.parse(entry.value.toString());

        // Normalize fields based on prefix type
        let action = "unknown";
        let targetUserId = value.targetUserId || "unknown";
        let opaRequest = null;
        let opaResponse = null;

        if (prefix === "mcp-policy:") {
          const decision = String(value.decision || (value.allow ? "ALLOW" : "DENY")).toLowerCase();
          const toolName = value.toolName || "unknown";
          action = `${decision}:${toolName}`;
          opaRequest = value.opaRequest;
          opaResponse = value.opaResponse;
        } else if (prefix === "mcp-alert:") {
          action = `alert:${value.toolName || "unknown"}`;
        } else {
          action = value.action || "unknown";
        }

        logs.push({
          source: "kv",
          key,
          authenticatedUser: value.authenticatedUser || "unknown",
          requesterIp: value.requesterIp || "unknown",
          targetUserId,
          action,
          status: value.status || null,
          durationMs: value.duration_ms ?? null,
          resultSummary: value.result_summary || null,
          errorCode: value.error_code || null,
          errorMessage: value.error_message || null,
          correlationId: value.correlation_id || null,
          reason: value.reason || null,
          reasons: value.reasons || null,
          policyVersion: value.policyVersion || null,
          triggeredControls: value.triggeredControls || null,
          requestId: value.requestId || null,
          actions: value.actions || null,
          risk: value.risk || null,
          opaRequest,
          opaResponse,
          timestamp: value.timestamp || "unknown"
        });
      } catch (e) {
        console.error("Failed to parse KV entry:", e.message);
      }
    });
  }

  return logs;
}

async function fetchSqlLogs(tableName) {
  const logs = [];
  let sqlQuery =
    `SELECT id, authenticated_user, requester_ip, target_user_id, action, status, duration_ms, result_summary, error_code, error_message, correlation_id, ts FROM ${tableName} ORDER BY id DESC LIMIT 100`;
  let parseRow = (row) => {
    const getId = (val) => val?.prop || val;
    const getStr = (val) => val?.prop || val || "unknown";
    const getNullableStr = (val) => (val?.prop ?? val ?? null);
    const getNumber = (val) => {
      const raw = val?.prop ?? val;
      if (raw === null || raw === undefined || raw === "") return null;
      const parsed = Number(raw);
      return Number.isFinite(parsed) ? parsed : null;
    };

    return {
      source: "sql",
      id: getId(row.id),
      authenticatedUser: getStr(row.authenticated_user),
      requesterIp: getStr(row.requester_ip),
      targetUserId: getStr(row.target_user_id),
      action: getStr(row.action),
      status: getNullableStr(row.status),
      durationMs: getNumber(row.duration_ms),
      resultSummary: getNullableStr(row.result_summary),
      errorCode: getNullableStr(row.error_code),
      errorMessage: getNullableStr(row.error_message),
      correlationId: getNullableStr(row.correlation_id),
      timestamp: getStr(row.ts)
    };
  };

  if (tableName === "mcp_policy_decisions") {
    sqlQuery =
      "SELECT id, request_id, authenticated_user, requester_ip, tool_name, target_user_id, allow, decision, reason, reasons, policy_version, triggered_controls, opa_request, opa_response, ts FROM mcp_policy_decisions ORDER BY id DESC LIMIT 100";
    parseRow = (row) => {
      const getId = (val) => val?.prop || val;
      const getStr = (val) => val?.prop || val || "unknown";
      const getNullableStr = (val) => (val?.prop ?? val ?? null);
      const allowRaw = getStr(row.allow);
      const decisionRaw = getNullableStr(row.decision);
      const allowNormalized = String(allowRaw).toLowerCase() === "true" ? "allow" : "deny";
      const decision = decisionRaw ? String(decisionRaw).toLowerCase() : allowNormalized;
      const toolName = getStr(row.tool_name);
      const reason = getStr(row.reason);

      return {
        source: "sql",
        id: getId(row.id),
        requestId: getNullableStr(row.request_id),
        authenticatedUser: getStr(row.authenticated_user),
        requesterIp: getStr(row.requester_ip),
        targetUserId: getStr(row.target_user_id),
        action: `${decision}:${toolName}`,
        reason,
        reasons: getNullableStr(row.reasons),
        policyVersion: getNullableStr(row.policy_version),
        triggeredControls: getNullableStr(row.triggered_controls),
        opaRequest: getNullableStr(row.opa_request),
        opaResponse: getNullableStr(row.opa_response),
        timestamp: getStr(row.ts)
      };
    };
  }



  if (tableName === "mcp_alerts") {
    sqlQuery =
      "SELECT id, request_id, authenticated_user, requester_ip, tool_name, reason, reasons, actions, risk, ts FROM mcp_alerts ORDER BY id DESC LIMIT 100";
    parseRow = (row) => {
      const getId = (val) => val?.prop || val;
      const getStr = (val) => val?.prop || val || "unknown";
      const getNullableStr = (val) => (val?.prop ?? val ?? null);

      return {
        source: "sql",
        id: getId(row.id),
        requestId: getNullableStr(row.request_id),
        authenticatedUser: getStr(row.authenticated_user),
        requesterIp: getStr(row.requester_ip),
        targetUserId: "security",
        action: `alert:${getStr(row.tool_name)}`,
        reason: getStr(row.reason),
        reasons: getNullableStr(row.reasons),
        actions: getNullableStr(row.actions),
        risk: getNullableStr(row.risk),
        timestamp: getStr(row.ts)
      };
    };
  }

  try {
    const sqlResult = await immudbClient.SQLQuery({
      sql: sqlQuery
    });

    if (sqlResult) {
      sqlResult.forEach((row) => {
        logs.push(parseRow(row));
      });
    }
  } catch (error) {
    // If it's a policy decisions table and the query fails, might be missing opa_request/opa_response columns
    // Try again if we haven't already (to avoid infinite retry)
    if (tableName === "mcp_actions" && sqlQuery.includes("status")) {
      console.warn("Actions query with extended columns failed, retrying without them...");
      const sqlQueryFallback =
        `SELECT id, authenticated_user, requester_ip, target_user_id, action, ts FROM ${tableName} ORDER BY id DESC LIMIT 100`;
      const sqlResult = await immudbClient.SQLQuery({
        sql: sqlQueryFallback
      });

      if (sqlResult) {
        sqlResult.forEach((row) => {
          logs.push(parseRow(row));
        });
      }
    } else if (tableName === "mcp_policy_decisions" && sqlQuery.includes("opa_request")) {
      console.warn("Policy decisions query with OPA columns failed, retrying without them...");
      const sqlQueryFallback =
        "SELECT id, authenticated_user, requester_ip, tool_name, target_user_id, allow, reason, ts FROM mcp_policy_decisions ORDER BY id DESC LIMIT 100";
      const sqlResult = await immudbClient.SQLQuery({
        sql: sqlQueryFallback
      });

      if (sqlResult) {
        sqlResult.forEach((row) => {
          logs.push(parseRow(row));
        });
      }
    } else {
      throw error;
    }
  }

  return logs;
}

app.get("/api/logs", async (req, res) => {
  try {
    if (!immudbClient) {
      await connectImmuDBWithRetry();
    }
    if (!immudbClient) {
      return res.status(503).json({ error: "immuDB not connected" });
    }

    const logs = [];
    const source = (req.query.source || "both").toString().toLowerCase();
    const kvPrefix = (req.query.prefix || "mcp-action:").toString();
    const requestedTable = (req.query.table || "mcp_actions").toString();

    if ((source === "sql" || source === "both") && !isSafeSqlIdentifier(requestedTable)) {
      return res.status(400).json({ error: "Invalid SQL table name" });
    }

    if (source === "sql" || source === "both") {
      const tables = await immudbClient.SQLListTables();
      const tableNames = (tables || []).map((table) => table?.name || table).filter(Boolean);
      if (!tableNames?.includes(requestedTable)) {
        return res.status(400).json({ error: `SQL table not found: ${requestedTable}` });
      }
    }

    if (source === "kv" || source === "both") {
      try {
        const kvLogs = await fetchKvLogs(kvPrefix);
        logs.push(...kvLogs);
      } catch (error) {
        if (error.code === 7 && error.details?.includes("token has expired")) {
          console.log("Token expired during KV fetch, re-authenticating...");
          await reAuthenticateImmuDB();
          try {
            const kvLogs = await fetchKvLogs(kvPrefix);
            logs.push(...kvLogs);
          } catch (retryError) {
            console.error("Failed to fetch KV logs after retry:", retryError.message);
          }
        } else {
          console.error("Failed to fetch KV logs:", error.message);
        }
      }
    }

    if (source === "sql" || source === "both") {
      try {
        const sqlLogs = await fetchSqlLogs(requestedTable);
        logs.push(...sqlLogs);
      } catch (error) {
        if (error.code === 7 && error.details?.includes("token has expired")) {
          console.log("Token expired during SQL fetch, re-authenticating...");
          await reAuthenticateImmuDB();
          try {
            const sqlLogs = await fetchSqlLogs(requestedTable);
            logs.push(...sqlLogs);
          } catch (retryError) {
            console.error("Failed to fetch SQL logs after retry:", retryError.message);
          }
        } else {
          console.error("Failed to fetch SQL logs:", error.message);
        }
      }
    }

    logs.sort((a, b) => {
      const timeA = new Date(a.timestamp || a.ts).getTime();
      const timeB = new Date(b.timestamp || b.ts).getTime();
      return timeB - timeA;
    });

    res.json({
      count: logs.length,
      logs: logs.slice(0, 100)
    });
  } catch (error) {
    console.error("API error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/health", (_req, res) => {
  res.json({
    status: immudbClient ? "ok" : "disconnected",
    immudb: immudbClient ? "connected" : "not connected"
  });
});

(async () => {
  try {
    console.log("Starting Log Viewer initialization...");
    immudbClient = await initImmuDB();
    if (!immudbClient) {
      await connectImmuDBWithRetry();
    }
    console.log("immuDB client initialized");

    const server = app.listen(PORT, () => {
      console.log(`Log Viewer running at http://localhost:${PORT}`);
      console.log(`View audit logs at http://localhost:${PORT}/index.html`);
      if (!immudbClient) {
        console.warn("immuDB not connected - logs will not be available");
      }
    });

    server.on("error", (error) => {
      console.error("Server error:", error);
      process.exit(1);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
})();

process.on("SIGINT", () => {
  console.log("Log Viewer shutting down...");
  process.exit(0);
});
