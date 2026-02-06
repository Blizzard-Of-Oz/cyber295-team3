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
      res.json({ tables });
    } catch (error) {
      if (error.code === 7 && error.details?.includes("token has expired")) {
        console.log("Token expired, re-authenticating...");
        await reAuthenticateImmuDB();
        const tables = await immudbClient.SQLListTables();
        res.json({ tables });
      } else {
        throw error;
      }
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/logs", async (_req, res) => {
  try {
    if (!immudbClient) {
      await connectImmuDBWithRetry();
    }
    if (!immudbClient) {
      return res.status(503).json({ error: "immuDB not connected" });
    }

    const logs = [];

    try {
      const kvResult = await immudbClient.scan({
        prefix: "mcp-action:",
        limit: 100,
        desc: true
      });

      if (kvResult?.entriesList && kvResult.entriesList.length > 0) {
        kvResult.entriesList.forEach((entry) => {
          try {
            const key = entry.key.toString();
            const value = JSON.parse(entry.value.toString());
            logs.push({
              source: "kv",
              key,
              ...value
            });
          } catch (e) {
            console.error("Failed to parse KV entry:", e.message);
          }
        });
      }
    } catch (error) {
      if (error.code === 7 && error.details?.includes("token has expired")) {
        console.log("Token expired during KV fetch, re-authenticating...");
        await reAuthenticateImmuDB();
        try {
          const kvResult = await immudbClient.scan({
            prefix: "mcp-action:",
            limit: 100,
            desc: true
          });
          if (kvResult?.entriesList && kvResult.entriesList.length > 0) {
            kvResult.entriesList.forEach((entry) => {
              try {
                const key = entry.key.toString();
                const value = JSON.parse(entry.value.toString());
                logs.push({
                  source: "kv",
                  key,
                  ...value
                });
              } catch (e) {
                console.error("Failed to parse KV entry:", e.message);
              }
            });
          }
        } catch (retryError) {
          console.error("Failed to fetch KV logs after retry:", retryError.message);
        }
      } else {
        console.error("Failed to fetch KV logs:", error.message);
      }
    }

    try {
      const sqlResult = await immudbClient.SQLQuery({
        sql:
          "SELECT id, authenticated_user, requester_ip, target_user_id, action, ts FROM mcp_actions ORDER BY id DESC LIMIT 100"
      });

      if (sqlResult) {
        sqlResult.forEach((row) => {
          const getId = (val) => val?.prop || val;
          const getStr = (val) => val?.prop || val || "unknown";

          logs.push({
            source: "sql",
            id: getId(row.id),
            authenticatedUser: getStr(row.authenticated_user),
            requesterIp: getStr(row.requester_ip),
            targetUserId: getStr(row.target_user_id),
            action: getStr(row.action),
            timestamp: getStr(row.ts)
          });
        });
      }
    } catch (error) {
      if (error.code === 7 && error.details?.includes("token has expired")) {
        console.log("Token expired during SQL fetch, re-authenticating...");
        await reAuthenticateImmuDB();
        try {
          const sqlResult = await immudbClient.SQLQuery({
            sql:
              "SELECT id, authenticated_user, requester_ip, target_user_id, action, ts FROM mcp_actions ORDER BY id DESC LIMIT 100"
          });
          if (sqlResult) {
            sqlResult.forEach((row) => {
              const getId = (val) => val?.prop || val;
              const getStr = (val) => val?.prop || val || "unknown";
              logs.push({
                source: "sql",
                id: getId(row.id),
                authenticatedUser: getStr(row.authenticated_user),
                requesterIp: getStr(row.requester_ip),
                targetUserId: getStr(row.target_user_id),
                action: getStr(row.action),
                timestamp: getStr(row.ts)
              });
            });
          }
        } catch (retryError) {
          console.error("Failed to fetch SQL logs after retry:", retryError.message);
        }
      } else {
        console.error("Failed to fetch SQL logs:", error.message);
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
