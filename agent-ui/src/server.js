import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import crypto from "crypto";
import fs from "fs/promises";
import os from "os";
import * as msal from "@azure/msal-node";
import { McpClientManager } from "./mcp-client.js";
import { createAgent } from "./agent.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.PORT || 5000;
const DEBUG = process.env.DEBUG === "true";
const DEFAULT_ATTACHMENT_SANDBOX_ROOT = path.join(os.tmpdir(), "agent-ui-attachments");
const AGENT_UPLOAD_TEMP_DIR = process.env.AGENT_UPLOAD_TEMP_DIR || DEFAULT_ATTACHMENT_SANDBOX_ROOT;
const ATTACHMENT_SANDBOX_SOURCE = process.env.AGENT_UPLOAD_TEMP_DIR
  ? "AGENT_UPLOAD_TEMP_DIR"
  : "default";

const msalConfig = {
  auth: {
    clientId: process.env.AZURE_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}`,
    clientSecret: process.env.AZURE_CLIENT_SECRET
  },
  system: {
    loggerOptions: {
      loggerCallback(_loglevel, message, containsPii) {
        if (containsPii) return;
        if (DEBUG) {
          console.log(`[agent-ui][msal] ${message}`);
        }
      },
      piiLoggingEnabled: false,
      logLevel: msal.LogLevel.Warning
    }
  }
};

const msalInstance = new msal.ConfidentialClientApplication(msalConfig);

function debugLog(message, meta) {
  if (!DEBUG) return;
  console.log("\n---");
  if (meta !== undefined) {
    try {
      console.log(`[agent-ui][debug] ${message}`, JSON.stringify(meta, null, 2));
    } catch {
      console.log(`[agent-ui][debug] ${message}`, meta);
    }
  } else {
    console.log(`[agent-ui][debug] ${message}`);
  }
  console.log("---");
}

const mcpClientManager = new McpClientManager();
const agent = createAgent({ mcpClientManager });

app.use(express.json({ limit: process.env.REQUEST_JSON_LIMIT || "15mb" }));
app.use(express.static(path.join(__dirname, "..", "web")));

app.set("trust proxy", true);

app.use((_req, res, next) => {
  res.set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
  next();
});

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

app.use((req, _res, next) => {
  debugLog("HTTP request", {
    method: req.method,
    url: req.url,
    ip: req.ip
  });
  next();
});

function getRedirectUri(req) {
  if (process.env.REDIRECT_URI) return process.env.REDIRECT_URI;
  const protocol = req.protocol;
  const host = req.get("host");
  return `${protocol}://${host}/auth/callback`;
}

function getPostLogoutRedirectUri(req) {
  if (process.env.POST_LOGOUT_REDIRECT_URI) {
    return process.env.POST_LOGOUT_REDIRECT_URI;
  }
  const protocol = req.protocol;
  const host = req.get("host");
  return `${protocol}://${host}`;
}

function getClientIp(req) {
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

function sanitizeAttachmentName(name) {
  if (typeof name !== "string") return "attachment.bin";
  const normalized = path.basename(name).replace(/[^a-zA-Z0-9._-]/g, "_");
  return normalized || "attachment.bin";
}

function createUniqueFilename(baseName, usedNames, fallbackIndex) {
  const initial = sanitizeAttachmentName(baseName || `attachment-${fallbackIndex}.bin`);
  if (!usedNames.has(initial)) {
    usedNames.add(initial);
    return initial;
  }

  const extension = path.extname(initial);
  const stem = extension ? initial.slice(0, -extension.length) : initial;
  let counter = 1;
  while (true) {
    const candidate = `${stem}-${counter}${extension}`;
    if (!usedNames.has(candidate)) {
      usedNames.add(candidate);
      return candidate;
    }
    counter += 1;
  }
}

async function materializeRequestAttachments(req) {
  const payload = Array.isArray(req.body?.attachments) ? req.body.attachments : [];
  const tempRoot = AGENT_UPLOAD_TEMP_DIR;
  await fs.mkdir(tempRoot, { recursive: true, mode: 0o700 });
  await fs.chmod(tempRoot, 0o700).catch(() => {});

  // Create a per-request random directory with restrictive permissions.
  const requestDir = await fs.mkdtemp(path.join(tempRoot, "req-"));
  await fs.chmod(requestDir, 0o700).catch(() => {});

  if (payload.length === 0) {
    return { paths: [], metadata: [], requestDir, cleanup: async () => {
      await fs.rm(requestDir, { recursive: true, force: true });
    } };
  }

  const paths = [];
  const metadata = [];
  const usedNames = new Set();
  for (let i = 0; i < payload.length; i += 1) {
    const entry = payload[i] || {};
    const base64 = typeof entry.contentBase64 === "string" ? entry.contentBase64 : "";
    if (!base64) continue;
    const fileBytes = Buffer.from(base64, "base64");
    const filename = createUniqueFilename(entry.name, usedNames, i + 1);
    const filePath = path.join(requestDir, filename);
    await fs.writeFile(filePath, fileBytes, { mode: 0o600 });
    paths.push(filePath);

    const displayName = typeof entry.displayName === "string" && entry.displayName.trim()
      ? entry.displayName.trim()
      : filename;
    const displaySize = Number(entry.displaySizeBytes);
    metadata.push({
      path: filePath,
      displayName,
      displaySizeBytes: Number.isFinite(displaySize) && displaySize >= 0 ? displaySize : fileBytes.length
    });
  }

  return {
    paths,
    metadata,
    requestDir,
    cleanup: async () => {
      await fs.rm(requestDir, { recursive: true, force: true });
    }
  };
}

function isAuthenticated(req, res, next) {
  if (req.session?.account) return next();
  return res.status(401).json({ error: "Not authenticated", requiresAuth: true });
}

function ensureCsrfToken(req) {
  if (!req.session?.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrfToken;
}

function requireCsrf(req, res, next) {
  const token = req.get("x-csrf-token");
  if (!token || token !== req.session?.csrfToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  return next();
}

app.use((req, res, next) => {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
    return next();
  }
  return requireCsrf(req, res, next);
});

app.get("/auth/signin", async (req, res) => {
  const redirectUri = getRedirectUri(req);
  const authCodeUrlParameters = {
    scopes: ["user.read"],
    redirectUri
  };

  try {
    const authCodeUrl = await msalInstance.getAuthCodeUrl(authCodeUrlParameters);
    res.redirect(authCodeUrl);
  } catch (error) {
    debugLog("Auth signin failed", { error: error?.message || error });
    res.status(500).send("Authentication error");
  }
});

app.get("/auth/callback", async (req, res) => {
  const redirectUri = getRedirectUri(req);
  const tokenRequest = {
    code: req.query.code,
    scopes: ["user.read"],
    redirectUri
  };

  try {
    const response = await msalInstance.acquireTokenByCode(tokenRequest);
    req.session.account = response.account;
    req.session.accessToken = response.accessToken;
    ensureCsrfToken(req);
    res.redirect("/");
  } catch (error) {
    debugLog("Auth callback failed", { error: error?.message || error });
    res.status(500).send("Authentication error");
  }
});

app.get("/auth/signout", (_req, res) => {
  res.status(405).send("Use POST /auth/signout");
});

app.post("/auth/signout", (req, res) => {
  const postLogoutRedirectUri = getPostLogoutRedirectUri(req);
  req.session.destroy((err) => {
    if (err) {
      debugLog("Session destroy failed", { error: err?.message || err });
    }
    const logoutUri = `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent(postLogoutRedirectUri)}`;
    res.redirect(logoutUri);
  });
});

app.get("/api/health", (req, res) => {
  debugLog("Health check");
  res.json({ status: "ok", authenticated: Boolean(req.session?.account) });
});

app.get("/api/csrf", (req, res) => {
  const token = ensureCsrfToken(req);
  res.json({ token });
});

app.get("/api/user", isAuthenticated, (req, res) => {
  res.json({
    user: {
      name: req.session.account?.name,
      username: req.session.account?.username
    }
  });
});

app.post("/api/assist", isAuthenticated, async (req, res) => {
  const requirement = req.body?.requirement?.trim();
  if (!requirement) {
    return res.status(400).json({ error: "requirement is required" });
  }

  let uploaded = { paths: [], metadata: [], cleanup: async () => {} };

  try {
    uploaded = await materializeRequestAttachments(req);
    debugLog("Agent run started", { requirementLength: requirement.length });
    const requesterIp = getClientIp(req);
    const authenticatedUser =
      req.session?.account?.username || req.session?.account?.name || "unknown";
    const entraToken = req.session?.accessToken || "";

    const extraAttachmentPaths = Array.isArray(req.body?.attachmentPaths)
      ? req.body.attachmentPaths.filter((v) => typeof v === "string" && v.trim().length > 0)
      : [];

    const availableAttachmentPaths = [...uploaded.paths, ...extraAttachmentPaths];
    const availableAttachmentMetadata = [
      ...uploaded.metadata,
      ...extraAttachmentPaths.map((filePath) => ({
        path: filePath,
        displayName: path.basename(filePath),
        displaySizeBytes: 0
      }))
    ];

    const result = await agent.run(requirement, {
      authenticatedUser,
      entraToken,
      requesterIp,
      availableAttachmentPaths,
      availableAttachmentMetadata,
      generatedAttachmentDir: uploaded.requestDir
    });
    debugLog("Agent run completed", {
      toolCalls: result?.toolCalls?.length || 0,
      uploadedAttachmentCount: uploaded.paths.length,
      availableAttachmentCount: availableAttachmentPaths.length
    });
    return res.json({
      ...result,
      attachmentPathsUsed: availableAttachmentPaths
    });
  } catch (error) {
    debugLog("Agent run failed", { error: error?.message || error });
    return res.status(500).json({
      error: error?.message || "Unknown error"
    });
  } finally {
    await uploaded.cleanup().catch((cleanupError) => {
      debugLog("Attachment temp cleanup failed", { error: cleanupError?.message || cleanupError });
    });
  }
});

app.listen(port, () => {
  console.log(`Agent UI server running on http://localhost:${port}`);
  console.log(
    `[agent-ui] Attachment sandbox root: ${AGENT_UPLOAD_TEMP_DIR} (source=${ATTACHMENT_SANDBOX_SOURCE})`
  );
  if (DEBUG) {
    console.log("[agent-ui][debug] Debug logging enabled");
  }
});
