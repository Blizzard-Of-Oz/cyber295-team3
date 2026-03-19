import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import * as tar from "tar";
import yauzl from "yauzl";
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
const DEFAULT_ATTACHMENT_SANDBOX_ROOT = path.join(os.tmpdir(), "agent-ui-attachments");
const ATTACHMENT_SANDBOX_ROOT = path.resolve(
  process.env.ATTACHMENT_SANDBOX_ROOT || DEFAULT_ATTACHMENT_SANDBOX_ROOT
);
const ATTACHMENT_SANDBOX_SOURCE = process.env.ATTACHMENT_SANDBOX_ROOT
      ? "ATTACHMENT_SANDBOX_ROOT"
    : "default";
const SENSITIVE_HEADER_NAMES = [
  "authorization",
  "x-entra-token",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "x-api-key"
];
const URL_REGEX = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const BASE64ISH_REGEX = /^(?:[A-Za-z0-9+/_-]{12,}={0,2})$/;
const LONG_QUERY_STRING_THRESHOLD = 80;
const SUSPICIOUS_QUERY_VALUE_LENGTH = 24;
const HIGH_ENTROPY_SUBDOMAIN_THRESHOLD = 3.3;
const HIGH_ENTROPY_SUBDOMAIN_LENGTH = 12;
const SUSPICIOUS_DOMAIN_KEYWORDS = [
  "exfil",
  "c2",
  "command-and-control",
  "beacon",
  "payload",
  "tunnel",
  "dns",
  "covert",
  "steal",
  "drop",
  "collector"
];

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

function collectRequestHeaders(req) {
  const headers = {};
  for (const [key, value] of Object.entries(req.headers || {})) {
    const normalizedKey = String(key).toLowerCase();
    headers[normalizedKey] = value;
  }
  return headers;
}

function buildHttpRequestSnapshot(req) {
  return {
    method: req.method,
    path: req.path,
    original_url: req.originalUrl,
    protocol: req.protocol,
    http_version: req.httpVersion,
    host: req.get?.("host") || req.headers?.host || null,
    headers: collectRequestHeaders(req),
    query: req.query || {},
    params: req.params || {},
    body: req.body || null
  };
}

function redactHeaders(headers = {}) {
  const redacted = { ...headers };
  for (const headerName of SENSITIVE_HEADER_NAMES) {
    if (redacted[headerName]) redacted[headerName] = "[redacted]";
  }
  return redacted;
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

const URGENCY_KEYWORDS = [
  "URGENT",
  "IMMEDIATELY",
  "DO NOT DELAY",
  "CEO DEMANDS",
  "NOW"
];

function detectUrgencySignals(contentText = "", userInput = "") {
  const text = `${contentText}\n${userInput}`.toUpperCase();
  const matched_keywords = URGENCY_KEYWORDS.filter((keyword) => text.includes(keyword));
  return {
    matched_keywords,
    urgency_score: matched_keywords.length * 2
  };
}

function extractUrlsFromText(...parts) {
  const urls = [];
  const seen = new Set();

  for (const part of parts) {
    if (typeof part !== "string" || !part.trim()) continue;
    for (const match of part.matchAll(URL_REGEX)) {
      const url = match[0];
      if (seen.has(url)) continue;
      seen.add(url);
      urls.push(url);
    }
  }

  return urls;
}

function sanitizeHostnamePart(part) {
  if (typeof part !== "string") return "";
  return part.trim().replace(/^\.+|\.+$/g, "");
}

function shannonEntropy(value) {
  if (typeof value !== "string" || value.length === 0) return 0;
  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return Number(entropy.toFixed(3));
}

function looksBase64ish(value, minLength = SUSPICIOUS_QUERY_VALUE_LENGTH) {
  if (typeof value !== "string") return false;
  const normalized = value.trim();
  if (normalized.length < minLength) return false;
  return BASE64ISH_REGEX.test(normalized);
}

function collectSuspiciousKeywords(...parts) {
  const haystack = parts
    .filter((part) => typeof part === "string" && part.trim())
    .map((part) => part.toLowerCase())
    .join("\n");

  return SUSPICIOUS_DOMAIN_KEYWORDS.filter((keyword) => haystack.includes(keyword));
}

function analyzeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const hostname = sanitizeHostnamePart(parsed.hostname.toLowerCase());
    const hostParts = hostname.split(".").filter(Boolean);
    const domain = hostParts.length >= 2 ? hostParts.slice(-2).join(".") : hostname;
    const subdomain = hostParts.length > 2 ? hostParts.slice(0, -2).join(".") : "";
    const queryEntries = Array.from(parsed.searchParams.entries());
    const queryValues = queryEntries.map(([, value]) => value);
    const suspiciousQueryValues = queryValues.filter((value) => looksBase64ish(value));
    const queryString = parsed.search.startsWith("?") ? parsed.search.slice(1) : parsed.search;
    const subdomainEntropy = shannonEntropy(subdomain);
    const looksBase64Subdomain = looksBase64ish(subdomain, 10);
    const highEntropySubdomain =
      subdomain.length >= HIGH_ENTROPY_SUBDOMAIN_LENGTH &&
      subdomainEntropy >= HIGH_ENTROPY_SUBDOMAIN_THRESHOLD;
    const longQueryString = queryString.length >= LONG_QUERY_STRING_THRESHOLD;
    const suspiciousQueryPayload = suspiciousQueryValues.length > 0;
    const suspiciousDomainKeywords = collectSuspiciousKeywords(hostname, domain, rawUrl);
    const suspiciousDomainPattern = suspiciousDomainKeywords.length > 0;
    const suspiciousHostnamePattern = suspiciousDomainKeywords.some((keyword) => hostname.includes(keyword));

    return {
      original_url: rawUrl,
      hostname,
      domain,
      subdomain,
      query_string_length: queryString.length,
      query_param_count: queryEntries.length,
      query_param_keys: queryEntries.map(([key]) => key),
      query_values_look_base64: suspiciousQueryPayload,
      suspicious_query_value_lengths: suspiciousQueryValues.map((value) => value.length),
      subdomain_length: subdomain.length,
      subdomain_entropy: subdomainEntropy,
      suspicious_domain_keywords: suspiciousDomainKeywords,
      suspicious_domain_pattern: suspiciousDomainPattern,
      suspicious_hostname_pattern: suspiciousHostnamePattern,
      looks_base64_subdomain: looksBase64Subdomain,
      high_entropy_subdomain: highEntropySubdomain,
      long_query_string: longQueryString,
      suspicious_query_payload: suspiciousQueryPayload
    };
  } catch {
    return null;
  }
}

function analyzeUrls(parts) {
  const analyzed = extractUrlsFromText(...parts).map(analyzeUrl).filter(Boolean);
  const flagged = analyzed.filter(
    (entry) =>
      entry.looks_base64_subdomain ||
      entry.high_entropy_subdomain ||
      entry.suspicious_domain_pattern ||
      entry.suspicious_hostname_pattern ||
      entry.long_query_string ||
      entry.suspicious_query_payload
  );

  return {
    urls: analyzed,
    dnsTunnelingDetected: flagged.length > 0,
    dnsTunnelingSignals: {
      url_count: analyzed.length,
      flagged_url_count: flagged.length,
      flagged_reasons: {
        base64_subdomain_count: flagged.filter((entry) => entry.looks_base64_subdomain).length,
        high_entropy_subdomain_count: flagged.filter((entry) => entry.high_entropy_subdomain).length,
        suspicious_domain_pattern_count: flagged.filter((entry) => entry.suspicious_domain_pattern).length,
        suspicious_hostname_pattern_count: flagged.filter((entry) => entry.suspicious_hostname_pattern).length,
        long_query_string_count: flagged.filter((entry) => entry.long_query_string).length,
        suspicious_query_payload_count: flagged.filter((entry) => entry.suspicious_query_payload).length
      }
    }
  };
}

function resolveCanonicalPathIfExists(targetPath) {
  try {
    return fs.realpathSync(targetPath);
  } catch (_error) {
    return targetPath;
  }
}

function getAttachmentSandboxRoots() {
  const lexicalRoot = ATTACHMENT_SANDBOX_ROOT;
  const canonicalRoot = resolveCanonicalPathIfExists(ATTACHMENT_SANDBOX_ROOT);
  return { lexicalRoot, canonicalRoot };
}

function isPathWithinDirectory(targetPath, directoryPath) {
  const relative = path.relative(directoryPath, targetPath);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function validateAttachmentPath(filePath) {
  const normalized = typeof filePath === "string" ? filePath.trim() : "";
  if (!normalized) {
    return { allowed: false, reason: "empty_path" };
  }

  const { lexicalRoot, canonicalRoot } = getAttachmentSandboxRoots();
  const resolvedPath = path.resolve(normalized);
  const insideLexicalSandbox = isPathWithinDirectory(resolvedPath, lexicalRoot);
  const insideCanonicalSandbox = isPathWithinDirectory(resolvedPath, canonicalRoot);
  if (!insideLexicalSandbox && !insideCanonicalSandbox) {
    return {
      allowed: false,
      reason: "outside_sandbox",
      inputPath: normalized,
      resolvedPath
    };
  }

  try {
    const realPath = fs.realpathSync(resolvedPath);
    const insideRealLexicalSandbox = isPathWithinDirectory(realPath, lexicalRoot);
    const insideRealCanonicalSandbox = isPathWithinDirectory(realPath, canonicalRoot);
    if (!insideRealLexicalSandbox && !insideRealCanonicalSandbox) {
      return {
        allowed: false,
        reason: "outside_sandbox_symlink",
        inputPath: normalized,
        resolvedPath: realPath
      };
    }
  } catch (_error) {
    // If the file does not exist yet, keep the lexical path check result.
  }

  return {
    allowed: true,
    path: resolvedPath
  };
}

function enforceAttachmentSandbox(paths = []) {
  const allowedPaths = [];
  const rejectedPaths = [];

  for (const filePath of paths) {
    const validation = validateAttachmentPath(filePath);
    if (validation.allowed) {
      allowedPaths.push(validation.path);
    } else {
      rejectedPaths.push({
        path: typeof filePath === "string" ? filePath : "",
        reason: validation.reason,
        resolvedPath: validation.resolvedPath || null
      });
    }
  }

  return {
    allowedPaths: unique(allowedPaths),
    rejectedPaths
  };
}

function fileExtension(value) {
  if (typeof value !== "string" || value.trim() === "") return "";
  const ext = path.extname(value).toLowerCase();
  return ext.startsWith(".") ? ext.slice(1) : ext;
}

function isArchiveExtension(ext = "") {
  return ["zip", "7z", "rar", "tar", "tgz", "gz", "bz2", "xz"].includes(lower(ext));
}

function lower(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function toFixedNumber(value, digits = 4) {
  if (!Number.isFinite(value)) return null;
  return Number(value.toFixed(digits));
}

function buildArchiveMetadata({ containsFileTypes = [], fileCount = 0, passwordProtected = false, compressionRatio = null } = {}) {
  return {
    contains_file_types: unique(containsFileTypes.map((ext) => lower(ext)).filter(Boolean)).sort(),
    file_count: Number.isFinite(fileCount) ? fileCount : 0,
    password_protected: Boolean(passwordProtected),
    compression_ratio: compressionRatio
  };
}

async function inspectZipArchive(filePath) {
  return new Promise((resolve) => {
    yauzl.open(filePath, { lazyEntries: true, autoClose: true }, (openError, zipFile) => {
      if (openError || !zipFile) {
        resolve(null);
        return;
      }

      let fileCount = 0;
      let totalCompressedBytes = 0;
      let totalUncompressedBytes = 0;
      let passwordProtected = false;
      const containsFileTypes = [];

      zipFile.on("entry", (entry) => {
        if (!entry || /\/$/.test(entry.fileName || "")) {
          zipFile.readEntry();
          return;
        }

        fileCount += 1;
        totalCompressedBytes += Number(entry.compressedSize || 0);
        totalUncompressedBytes += Number(entry.uncompressedSize || 0);

        const entryExt = fileExtension(path.basename(entry.fileName || ""));
        if (entryExt) {
          containsFileTypes.push(entryExt);
        }

        if ((entry.generalPurposeBitFlag & 0x1) === 0x1) {
          passwordProtected = true;
        }

        zipFile.readEntry();
      });

      zipFile.on("end", () => {
        const compressionRatio =
          totalCompressedBytes > 0 ? toFixedNumber(totalUncompressedBytes / totalCompressedBytes) : null;
        resolve(
          buildArchiveMetadata({
            containsFileTypes,
            fileCount,
            passwordProtected,
            compressionRatio
          })
        );
      });

      zipFile.on("error", () => resolve(null));
      zipFile.readEntry();
    });
  });
}

function isTarLikeArchive(filePath, ext) {
  const normalizedPath = lower(filePath);
  if (ext === "tar" || ext === "tgz") return true;
  if (normalizedPath.endsWith(".tar.gz") || normalizedPath.endsWith(".tar.bz2") || normalizedPath.endsWith(".tar.xz")) {
    return true;
  }
  return false;
}

async function inspectTarArchive(filePath, archiveSizeBytes) {
  let fileCount = 0;
  let totalUncompressedBytes = 0;
  const containsFileTypes = [];

  try {
    await tar.t({
      file: filePath,
      onentry: (entry) => {
        if (!entry || entry.type !== "File") return;
        fileCount += 1;
        totalUncompressedBytes += Number(entry.size || 0);
        const entryExt = fileExtension(path.basename(entry.path || ""));
        if (entryExt) {
          containsFileTypes.push(entryExt);
        }
      }
    });

    const compressionRatio =
      archiveSizeBytes > 0 ? toFixedNumber(totalUncompressedBytes / archiveSizeBytes) : null;
    return buildArchiveMetadata({
      containsFileTypes,
      fileCount,
      passwordProtected: false,
      compressionRatio
    });
  } catch (_error) {
    return null;
  }
}

async function inspectArchiveMetadata(filePath, ext, archiveSizeBytes) {
  if (!filePath || !ext || !isArchiveExtension(ext)) return null;

  if (ext === "zip") {
    return inspectZipArchive(filePath);
  }

  if (isTarLikeArchive(filePath, ext)) {
    return inspectTarArchive(filePath, archiveSizeBytes);
  }

  return null;
}

function summarizeArchiveMetadata(attachments = []) {
  const archiveItems = attachments
    .map((attachment) => attachment?.archive)
    .filter((archive) => archive && typeof archive === "object");

  if (archiveItems.length === 0) {
    return {
      contains_file_types: [],
      file_count: 0,
      password_protected: false,
      compression_ratio: null
    };
  }

  const containsFileTypes = unique(
    archiveItems
      .flatMap((archive) => (Array.isArray(archive.contains_file_types) ? archive.contains_file_types : []))
      .map((ext) => lower(ext))
      .filter(Boolean)
  ).sort();

  const fileCount = archiveItems.reduce((sum, archive) => sum + Number(archive.file_count || 0), 0);
  const passwordProtected = archiveItems.some((archive) => Boolean(archive.password_protected));
  const compressionRatios = archiveItems
    .map((archive) => Number(archive.compression_ratio))
    .filter((ratio) => Number.isFinite(ratio) && ratio > 0);
  const compressionRatio =
    compressionRatios.length > 0
      ? toFixedNumber(compressionRatios.reduce((sum, ratio) => sum + ratio, 0) / compressionRatios.length)
      : null;

  return {
    contains_file_types: containsFileTypes,
    file_count: fileCount,
    password_protected: passwordProtected,
    compression_ratio: compressionRatio
  };
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

function normalizeProvidedAttachments(value) {
  if (!Array.isArray(value)) return [];

  return value
    .map((entry) => {
      if (typeof entry === "string") {
        const trimmed = entry.trim();
        if (!trimmed) return null;
        const name = path.basename(trimmed);
        const ext = fileExtension(name);
        return {
          path: trimmed,
          name,
          file_ext: ext,
          actual_ext: ext,
          detected_types: ext ? [ext] : []
        };
      }

      if (entry && typeof entry === "object") {
        const normalized = { ...entry };
        const name = normalized.name || normalized.filename || normalized.file_name;
        const ext = fileExtension(name || normalized.path || "");

        if (name && !normalized.name) normalized.name = name;
        if (!normalized.file_ext && ext) normalized.file_ext = ext;
        if (!normalized.actual_ext && normalized.file_ext) normalized.actual_ext = normalized.file_ext;
        if (!Array.isArray(normalized.detected_types) && normalized.file_ext) {
          normalized.detected_types = [normalized.file_ext];
        }

        return normalized;
      }

      return null;
    })
    .filter(Boolean);
}

async function deriveContextAttachments(req, args) {
  const provided = normalizeProvidedAttachments(req.body?.context?.attachments);
  const paths = unique(normalizeAttachmentPaths(args));

  const derived = paths.map((filePath) => {
    const name = path.basename(filePath);
    const ext = fileExtension(name);
    let sizeBytes = null;

    try {
      const stat = fs.statSync(filePath);
      if (stat.isFile()) {
        sizeBytes = stat.size;
      }
    } catch (_error) {
      // Keep attachment metadata even when file is inaccessible.
    }

    return {
      path: filePath,
      name,
      size_bytes: sizeBytes,
      file_ext: ext,
      actual_ext: ext,
      detected_types: ext ? [ext] : []
    };
  });

  const explicitName = args?.attachmentName || args?.attachment_name;
  const explicitBytes = Number(args?.attachmentBytes || args?.attachment_bytes || 0);
  if (derived.length === 0 && typeof explicitName === "string" && explicitName.trim()) {
    const normalizedName = explicitName.trim();
    const ext = fileExtension(normalizedName);
    derived.push({
      name: normalizedName,
      size_bytes: explicitBytes > 0 ? explicitBytes : null,
      file_ext: ext,
      actual_ext: ext,
      detected_types: ext ? [ext] : []
    });
  }

  const merged = [...provided, ...derived];
  const deduped = [];
  const seen = new Set();

  for (const attachment of merged) {
    const normalizedPath = typeof attachment.path === "string" ? attachment.path.trim() : "";
    const normalizedName = typeof attachment.name === "string" ? attachment.name.trim() : "";
    const key = normalizedPath ? `path:${normalizedPath}` : `name:${normalizedName}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(attachment);
  }

  for (const attachment of deduped) {
    const ext = lower(attachment.actual_ext || attachment.file_ext || fileExtension(attachment.name || attachment.path || ""));
    if (!isArchiveExtension(ext)) continue;
    if (attachment.archive && typeof attachment.archive === "object") continue;
    if (!attachment.path || typeof attachment.path !== "string") continue;

    const archive = await inspectArchiveMetadata(
      attachment.path,
      ext,
      Number(attachment.size_bytes || 0)
    );

    if (archive) {
      attachment.archive = archive;
    }
  }

  return deduped;
}

function normalizeToolArguments(name, args) {
  const normalized = args && typeof args === "object" ? { ...args } : {};
  if (name === "send_email" || name === "draft_email") {
    const attachmentPaths = normalizeAttachmentPaths(normalized);
    const { allowedPaths, rejectedPaths } = enforceAttachmentSandbox(attachmentPaths);

    if (rejectedPaths.length > 0) {
      const error = new Error(
        `Attachment paths must be within sandbox directory: ${ATTACHMENT_SANDBOX_ROOT}`
      );
      error.code = "invalid_attachment_path";
      error.statusCode = 400;
      error.details = {
        sandboxRoot: ATTACHMENT_SANDBOX_ROOT,
        rejectedPaths
      };
      throw error;
    }

    if (allowedPaths.length > 0) {
      normalized.attachments = allowedPaths;
    } else {
      delete normalized.attachments;
    }

    delete normalized.attachmentPath;
    delete normalized.attachment_path;
  }
  return normalized;
}

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

async function buildOpaInput(req, toolName, args) {
  const requesterIp = getRequesterIp(req);
  const authenticatedUser = getAuthenticatedUser(req);
  const httpRequest = buildHttpRequestSnapshot(req);
  const headers = httpRequest.headers;

  const recipients = unique([
    ...normalizeEmailList(args?.to),
    ...normalizeEmailList(args?.cc),
    ...normalizeEmailList(args?.bcc),
    ...normalizeEmailList(args?.message?.to)
  ]);
  const contentText = `${args?.subject || ""}\n${args?.body || ""}\n${args?.message?.body || ""}`;
  const userInput = req.body?.context?.userInput || null;
  const urgencySignals = detectUrgencySignals(contentText, userInput || "");
  const urlAnalysis = analyzeUrls([
    contentText,
    userInput,
    req.body?.context?.content_text,
    req.body?.context?.user_input
  ]);

  const attachmentMeta = deriveAttachmentMetadata(args);
  const contextAttachments = await deriveContextAttachments(req, args);

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
      ...httpRequest
    },
    context: {
      recipient_count: recipients.length,
      recipients,
      content_text: contentText,
      user_input: userInput,
      urgency_manipulation: urgencySignals.urgency_score >= 8,
      urgency_signals: urgencySignals,
      urls: urlAnalysis.urls,
      dns_tunneling_detected: urlAnalysis.dnsTunnelingDetected,
      dns_tunneling_signals: urlAnalysis.dnsTunnelingSignals,
      attachment_bytes: Number(attachmentMeta.attachmentBytes || 0),
      attachment_name: attachmentMeta.attachmentName,
      attachment_count: attachmentMeta.attachmentCount,
      attachments: contextAttachments,
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
  const headers = redactHeaders(input.request?.headers || {});

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

async function callOpaDecision(req, toolName, args, prebuiltInput = null) {
  if (!OPA_ENABLED) {
    return { allow: true, reason: "opa_disabled", raw: null };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), OPA_TIMEOUT_MS);
  const input = prebuiltInput || (await buildOpaInput(req, toolName, args));
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
let activeMcpClient = mcpClientManager;
let activeLogger = immudbLogger;

function createApp({ mcpClient = mcpClientManager, logger = immudbLogger } = {}) {
  activeMcpClient = mcpClient;
  activeLogger = logger;
  return app;
}

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
    const tools = await activeMcpClient.listTools();
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
    if (DEBUG) {
      const requestSnapshot = buildHttpRequestSnapshot(req);
      debugLog("Incoming HTTP request", {
        request: {
          ...requestSnapshot,
          headers: redactHeaders(requestSnapshot.headers)
        }
      });
    }

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

    const opaRequest = await buildOpaInput(req, name, normalizedArgs);
    const opaDecision = await callOpaDecision(req, name, normalizedArgs, opaRequest);
    const requesterIp = getRequesterIp(req);
    const targetUserId = deriveTarget(normalizedArgs);

    const requestId = req.body?.request_id || (demoRequestIdGenerator ? demoRequestIdGenerator.nextId() : `Request-${crypto.randomBytes(6).toString("hex")}`);
    activeLogger
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
      activeLogger.recordAlert({
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
      activeLogger
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

    const result = await activeMcpClient.callTool(name, normalizedArgs);
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

    activeLogger
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
    auditSummary = truncateText(error?.message || "tool call failed", 200);
    debugLog("Tool call failed", { error: error?.message || error });
    try {
      const { name, arguments: args } = req.body || {};
      const rawArgs = args && typeof args === "object" ? { ...args } : {};
      let argsForAudit = rawArgs;
      try {
        // Best-effort normalization for audit target extraction only.
        // If normalization fails (e.g., invalid attachment path), keep raw args.
        argsForAudit = normalizeToolArguments(name, rawArgs);
      } catch (_normalizeError) {
        argsForAudit = rawArgs;
      }
      const authenticatedUser = getAuthenticatedUser(req);
      const requesterIp = getRequesterIp(req);
      const targetUserId = deriveTarget(argsForAudit);
      activeLogger
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
    const statusCode = Number.isInteger(error?.statusCode) ? Number(error.statusCode) : 500;
    const payload = { error: error?.message || "Tool call failed", correlationId };
    if (error?.code) payload.code = error.code;
    if (error?.details) payload.details = error.details;
    res.status(statusCode).json(payload);
  }
});

let server = null;
const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
const isPm2Run = Boolean(process.env.pm_id || process.env.PM2_HOME);
const shouldStartServer = isDirectRun || isPm2Run;

if (shouldStartServer) {
  createApp();
  server = app.listen(port, () => {
    console.log(`Gmail MCP HTTP wrapper running at http://localhost:${port}`);
    const { canonicalRoot } = getAttachmentSandboxRoots();
    console.log(
      `[gmail-mcp-http] Attachment sandbox root: ${ATTACHMENT_SANDBOX_ROOT} (source=${ATTACHMENT_SANDBOX_SOURCE})`
    );
    if (canonicalRoot !== ATTACHMENT_SANDBOX_ROOT) {
      console.log(
        `[gmail-mcp-http] Attachment sandbox canonical root: ${canonicalRoot}`
      );
    }
    if (DEBUG) {
      console.log("[gmail-mcp-http][debug] Debug logging enabled");
    }
  });

  process.on("SIGINT", async () => {
    await mcpClientManager.close();
    await rateLimiter.close();
    server.close(() => process.exit(0));
  });
} else if (DEBUG) {
  console.log("[gmail-mcp-http][debug] Server startup skipped (module imported for tests)");
}

export {
  buildOpaInput,
  callOpaDecision,
  createApp,
  detectUrgencySignals,
  extractUrlsFromText,
  analyzeUrl,
  normalizeOpaDecision,
  redactOpaInput
};
