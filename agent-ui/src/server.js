import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import crypto from "crypto";
import * as msal from "@azure/msal-node";
import { McpClientManager } from "./mcp-client.js";
import { createAgent } from "./agent.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.PORT || 5000;
const DEBUG = process.env.DEBUG === "true";

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

app.use(express.json({ limit: "1mb" }));
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

  try {
    debugLog("Agent run started", { requirementLength: requirement.length });
    const requesterIp = getClientIp(req);
    const authenticatedUser =
      req.session?.account?.username || req.session?.account?.name || "unknown";
    const entraToken = req.session?.accessToken || "";
    const result = await agent.run(requirement, {
      authenticatedUser,
      entraToken,
      requesterIp
    });
    debugLog("Agent run completed", {
      toolCalls: result?.toolCalls?.length || 0
    });
    return res.json(result);
  } catch (error) {
    debugLog("Agent run failed", { error: error?.message || error });
    return res.status(500).json({
      error: error?.message || "Unknown error"
    });
  }
});

app.listen(port, () => {
  console.log(`Agent UI server running on http://localhost:${port}`);
  if (DEBUG) {
    console.log("[agent-ui][debug] Debug logging enabled");
  }
});
