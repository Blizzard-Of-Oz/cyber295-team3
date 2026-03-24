import path from "path";
import fs from "fs";
import os from "os";
import * as tar from "tar";
import yauzl from "yauzl";
import mammoth from "mammoth";
import { PDFParse } from "pdf-parse";
import { fileTypeFromBuffer, fileTypeFromFile } from "file-type";
import xlsx from "xlsx";

/**
 * Configuration constants for attachment handling
 */
export const ATTACHMENT_CONFIG = {
  DEFAULT_SANDBOX_ROOT: path.join(os.tmpdir(), "agent-ui-attachments"),
  TEXT_MAX_BYTES: 262144,
  STRUCTURED_TEXT_MAX_BYTES: 10 * 1024 * 1024,
  TEXT_MAX_CHARS: 8000,
  IMAGE_OCR_MODEL: "gpt-4.1-mini",
  IMAGE_OCR_TIMEOUT_MS: 10000,
  IMAGE_MAX_BYTES: 5 * 1024 * 1024,
  ARCHIVE_ENTRY_MAX_FILES: 50,
  ARCHIVE_ENTRY_MAX_BYTES: 262144,
  OPENAI_BASE_URL: "https://api.openai.com/v1",
  TEXT_EXTENSIONS: new Set([
    "txt", "md", "json", "csv", "log", "xml", "html", "htm",
    "yaml", "yml", "ini", "cfg", "conf", "tsv", "sql", "rtf", "cvs"
  ]),
  STRUCTURED_TEXT_EXTENSIONS: new Set(["pdf", "docx", "xlsx", "pptx"]),
  IMAGE_EXTENSIONS: new Set([
    "png", "jpg", "jpeg", "webp", "gif", "bmp", "tif", "tiff"
  ]),
  ARCHIVE_EXTENSIONS: ["zip", "7z", "rar", "tar", "tgz", "gz", "bz2", "xz"],
  OFFICE_FORMATS: {
    DOCX: { dirMarker: "word/", fileMarker: "word/document.xml" },
    XLSX: { dirMarker: "xl/", fileMarker: "xl/workbook.xml" },
    PPTX: { dirMarker: "ppt/", fileMarker: "ppt/presentation.xml" }
  }
};

/**
 * Utility Functions
 */
function lower(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function unique(array) {
  return [...new Set(array)];
}

function toFixedNumber(value, digits = 4) {
  if (!Number.isFinite(value)) return null;
  return Number(value.toFixed(digits));
}

function fileExtension(value) {
  if (typeof value !== "string" || value.trim() === "") return "";
  const ext = path.extname(value).toLowerCase();
  return ext.startsWith(".") ? ext.slice(1) : ext;
}

function sanitizeExtractedText(value) {
  if (typeof value !== "string") return "";
  return value
    .replace(/\u0000/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .trim();
}

function looksBinaryData(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return false;
  const sampleSize = Math.min(buffer.length, 4096);
  let suspicious = 0;

  for (let i = 0; i < sampleSize; i += 1) {
    const byte = buffer[i];
    if (byte === 0) {
      suspicious += 1;
      continue;
    }

    const isPrintableAscii = byte >= 32 && byte <= 126;
    const isWhitespace = byte === 9 || byte === 10 || byte === 13;
    const isExtendedLatin = byte >= 160;
    if (!isPrintableAscii && !isWhitespace && !isExtendedLatin) {
      suspicious += 1;
    }
  }

  return suspicious / sampleSize > 0.3;
}

function isSupportedExtractionType(ext) {
  const normalized = lower(ext || "");
  return (
    ATTACHMENT_CONFIG.TEXT_EXTENSIONS.has(normalized) ||
    ATTACHMENT_CONFIG.STRUCTURED_TEXT_EXTENSIONS.has(normalized) ||
    ATTACHMENT_CONFIG.IMAGE_EXTENSIONS.has(normalized)
  );
}

function trimExtractedText(value, maxChars = ATTACHMENT_CONFIG.TEXT_MAX_CHARS) {
  if (typeof value !== "string") return "";
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars)}...`;
}

function resolveCanonicalPathIfExists(targetPath) {
  try {
    return fs.realpathSync(targetPath);
  } catch (_error) {
    return null;
  }
}

/**
 * FileTypeDetector Class
 * Detects file types using magic bytes and internal structure validation
 */
export class FileTypeDetector {
  constructor(sandboxRoot = null, debugLog = null) {
    this.sandboxRoot = sandboxRoot || ATTACHMENT_CONFIG.DEFAULT_SANDBOX_ROOT;
    this.debugLog = debugLog || (() => {});
  }

  /**
   * Detect file type from buffer using magic bytes
   */
  async detectFromBuffer(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
      this.debugLog("File type detection skipped: empty buffer", {
        source: "detectFromBuffer"
      });
      return { ext: null, mime: null, confidence: 0, source: "empty" };
    }

    try {
      const result = await fileTypeFromBuffer(buffer);
      if (result) {
        this.debugLog("File type detected from magic bytes", {
          source: "detectFromBuffer",
          ext: result.ext,
          mime: result.mime,
          buffer_bytes: buffer.length
        });
        return {
          ext: result.ext,
          mime: result.mime,
          confidence: 1.0,
          source: "magic_bytes"
        };
      }
      this.debugLog("File type detection returned unknown", {
        source: "detectFromBuffer",
        buffer_bytes: buffer.length
      });
    } catch (_error) {
      this.debugLog("File type detection failed while reading magic bytes", {
        source: "detectFromBuffer",
        buffer_bytes: buffer.length
      });
    }

    return { ext: null, mime: null, confidence: 0, source: "unknown" };
  }

  /**
   * Detect file type from file path
   */
  async detectFromPath(filePath) {
    try {
      const buffer = await fs.promises.readFile(filePath);
      this.debugLog("Running file type detection for path", {
        source: "detectFromPath",
        path: filePath,
        buffer_bytes: buffer.length
      });
      return this.detectFromBuffer(buffer);
    } catch (_error) {
      this.debugLog("File type detection failed to read file path", {
        source: "detectFromPath",
        path: filePath
      });
      return { ext: null, mime: null, confidence: 0, source: "error" };
    }
  }

  /**
   * Shared type-selection strategy used by both direct attachments and archive entries.
   */
  async detectBestExtension(buffer, fallbackExt = "") {
    const fallback = lower(fallbackExt || "");
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
      return fallback || null;
    }

    const detected = await this.detectFromBuffer(buffer);
    let detectedExt = lower(detected.ext || "");

    if (detectedExt === "zip") {
      detectedExt = await this.refineZipFormat(buffer);
    }

    if (detectedExt) {
      return detectedExt;
    }

    const knownNonTextFallback =
      ATTACHMENT_CONFIG.IMAGE_EXTENSIONS.has(fallback) ||
      ATTACHMENT_CONFIG.STRUCTURED_TEXT_EXTENSIONS.has(fallback) ||
      ATTACHMENT_CONFIG.ARCHIVE_EXTENSIONS.includes(fallback);

    if (knownNonTextFallback) {
      return fallback;
    }

    if (!looksBinaryData(buffer)) {
      return fallback || "txt";
    }

    return fallback || "bin";
  }

  /**
   * Refine ZIP format to detect Office documents
   * Returns canonical type: docx, xlsx, pptx, or zip (real archive)
   */
  async refineZipFormat(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length < 30) {
      this.debugLog("ZIP refinement skipped: buffer too small", {
        source: "refineZipFormat",
        buffer_bytes: Buffer.isBuffer(buffer) ? buffer.length : 0
      });
      return "zip"; // Too small to be valid ZIP
    }

    try {
      this.debugLog("Refining ZIP format to check Office signatures", {
        source: "refineZipFormat",
        buffer_bytes: buffer.length
      });

      // Create a temporary stream to list ZIP entries
      return await new Promise((resolve) => {
        let foundOfficeFormat = null;

        yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipFile) => {
          if (err || !zipFile) {
            resolve("zip");
            return;
          }

          zipFile.on("entry", (entry) => {
            if (!foundOfficeFormat) {
              const name = entry.fileName || "";
              
              if (name.match(/^word\/document\.xml$/)) {
                foundOfficeFormat = "docx";
                this.debugLog("ZIP refinement matched Office signature", {
                  source: "refineZipFormat",
                  detected_ext: "docx",
                  marker: name
                });
              } else if (name.match(/^xl\/workbook\.xml$/)) {
                foundOfficeFormat = "xlsx";
                this.debugLog("ZIP refinement matched Office signature", {
                  source: "refineZipFormat",
                  detected_ext: "xlsx",
                  marker: name
                });
              } else if (name.match(/^ppt\/presentation\.xml$/)) {
                foundOfficeFormat = "pptx";
                this.debugLog("ZIP refinement matched Office signature", {
                  source: "refineZipFormat",
                  detected_ext: "pptx",
                  marker: name
                });
              }
            }
            zipFile.readEntry();
          });

          zipFile.on("end", () => {
            this.debugLog("ZIP refinement completed", {
              source: "refineZipFormat",
              detected_ext: foundOfficeFormat || "zip"
            });
            resolve(foundOfficeFormat || "zip");
          });

          zipFile.on("error", () => {
            this.debugLog("ZIP refinement failed while reading archive entries", {
              source: "refineZipFormat"
            });
            resolve("zip");
          });

          zipFile.readEntry();
        });
      });
    } catch (_error) {
      this.debugLog("ZIP refinement threw error", {
        source: "refineZipFormat"
      });
      return "zip";
    }
  }

  /**
   * Get canonical type from detect result
   */
  async getCanonicalType(detectionResult) {
    const ext = lower(detectionResult.ext || "");
    
    // If detected as ZIP, refine to check for Office formats
    if (ext === "zip" && detectionResult.source === "magic_bytes") {
      return "zip"; // Will be refined at extraction time
    }

    // Map extensions to canonical types
    const canonicalMap = {
      pdf: "pdf",
      docx: "docx",
      xlsx: "xlsx",
      pptx: "pptx",
      zip: "zip",
      "7z": "7z",
      rar: "rar",
      tar: "tar",
      tgz: "tar",
      gz: "gz",
      bz2: "bz2",
      xz: "xz",
      png: "image",
      jpg: "image",
      jpeg: "image",
      webp: "image",
      gif: "image",
      bmp: "image",
      tif: "image",
      tiff: "image"
    };

    return canonicalMap[ext] || "unknown";
  }

  /**
   * Validate file type by comparing magic bytes vs claimed extension
   */
  async validate(buffer, claimedExt) {
    const detected = await this.detectFromBuffer(buffer);
    const detectedExt = lower(detected.ext || "");
    const normalizedClaimed = lower(claimedExt || "");

    this.debugLog("Validating claimed extension against detected type", {
      source: "validate",
      claimed_ext: normalizedClaimed,
      detected_ext: detectedExt || null,
      detection_source: detected.source
    });

    // Exact match
    if (detectedExt === normalizedClaimed) {
      this.debugLog("File type validation matched", {
        source: "validate",
        claimed_ext: normalizedClaimed,
        detected_ext: detectedExt
      });
      return { detected: detectedExt, claimed: normalizedClaimed, matches: true };
    }

    // ZIP refinement for Office formats
    if (detectedExt === "zip" && ["docx", "xlsx", "pptx"].includes(normalizedClaimed)) {
      const refined = await this.refineZipFormat(buffer);
      this.debugLog("File type validation used ZIP refinement", {
        source: "validate",
        claimed_ext: normalizedClaimed,
        refined_detected_ext: refined,
        matches: refined === normalizedClaimed
      });
      return {
        detected: refined,
        claimed: normalizedClaimed,
        matches: refined === normalizedClaimed
      };
    }

    // Mismatch
    this.debugLog("File type validation mismatch", {
      source: "validate",
      claimed_ext: normalizedClaimed,
      detected_ext: detectedExt || null
    });
    return { detected: detectedExt, claimed: normalizedClaimed, matches: false };
  }

  /**
   * Get sanitized extension from path (fallback for when magic bytes unavailable)
   */
  getExtensionFromPath(filePath) {
    return fileExtension(filePath);
  }
}

/**
 * AttachmentMetadata Utilities
 */
export class AttachmentMetadata {
  static normalizeAttachmentPaths(args) {
    const raw = [];
    if (Array.isArray(args?.attachments)) raw.push(...args.attachments);
    if (typeof args?.attachmentPath === "string") raw.push(args.attachmentPath);
    if (typeof args?.attachment_path === "string") raw.push(args.attachment_path);
    return raw.map((v) => (typeof v === "string" ? v.trim() : "")).filter(Boolean);
  }

  static normalizeProvidedAttachments(value) {
    if (!Array.isArray(value)) return [];

    return value
      .map((entry) => {
        if (typeof entry === "string") {
          const trimmed = entry.trim();
          if (!trimmed) return null;
          const name = path.basename(trimmed);
          const ext = fileExtension(name);
          return { path: trimmed, name, file_ext: ext, actual_ext: ext, detected_types: ext ? [ext] : [] };
        }

        if (entry && typeof entry === "object") {
          const normalized = { ...entry };
          const name = normalized.name || normalized.filename || normalized.file_name;
          const ext = fileExtension(name || normalized.path || "");
          if (name && !normalized.name) normalized.name = name;
          if (!normalized.file_ext && ext) normalized.file_ext = ext;
          if (!normalized.actual_ext && normalized.file_ext) normalized.actual_ext = normalized.file_ext;
          normalized.detected_types = normalized.actual_ext ? [normalized.actual_ext] : [];
          return normalized;
        }

        return null;
      })
      .filter(Boolean);
  }

  static buildArchiveMetadata({
    containsFileTypes = [],
    fileCount = 0,
    passwordProtected = false,
    compressionRatio = null
  } = {}) {
    return {
      contains_file_types: unique(
        containsFileTypes.map((ext) => lower(ext)).filter(Boolean)
      ).sort(),
      file_count: Number.isFinite(fileCount) ? fileCount : 0,
      password_protected: Boolean(passwordProtected),
      compression_ratio: compressionRatio
    };
  }

  static summarizeArchiveMetadata(attachments = []) {
    const archiveItems = attachments
      .map((att) => att?.archive)
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
        .flatMap((archive) =>
          Array.isArray(archive.contains_file_types) ? archive.contains_file_types : []
        )
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

    return { contains_file_types: containsFileTypes, file_count: fileCount, password_protected: passwordProtected, compression_ratio: compressionRatio };
  }
}

/**
 * TextExtractor Class
 * Extracts text from various file formats with proper type detection
 */
export class TextExtractor {
  constructor(debugLog = null) {
    this.debugLog = debugLog || (() => {});
  }

  /**
   * Main entry point: extract from file path
   */
  async fromPath(attachment = {}) {
    if (!attachment || typeof attachment !== "object") return null;
    if (typeof attachment.extracted_text === "string" && attachment.extracted_text.trim()) {
      this.debugLog("Attachment text extraction skipped: extracted_text already provided", {
        name: attachment.name || null
      });
      return trimExtractedText(sanitizeExtractedText(attachment.extracted_text));
    }

    if (typeof attachment.path !== "string" || !attachment.path.trim()) return null;

    try {
      const stat = fs.statSync(attachment.path);
      if (!stat.isFile()) return null;
      const ext = lower(
        attachment.actual_ext || attachment.detected_ext || attachment.file_ext || fileExtension(attachment.path)
      );

      if (!isSupportedExtractionType(ext)) {
        this.debugLog("Attachment text extraction skipped due to unsupported file type", {
          name: attachment.name || path.basename(attachment.path),
          ext
        });
        return null;
      }

      const imageMaxBytes = Number(process.env.ATTACHMENT_IMAGE_MAX_BYTES || ATTACHMENT_CONFIG.IMAGE_MAX_BYTES);
      const textMaxBytes = Number(process.env.ATTACHMENT_TEXT_MAX_BYTES || ATTACHMENT_CONFIG.TEXT_MAX_BYTES);
      const structuredTextMaxBytes = Number(
        process.env.ATTACHMENT_STRUCTURED_MAX_BYTES || ATTACHMENT_CONFIG.STRUCTURED_TEXT_MAX_BYTES
      );

      let maxBytes = Number.isFinite(textMaxBytes) && textMaxBytes > 0
        ? textMaxBytes
        : ATTACHMENT_CONFIG.TEXT_MAX_BYTES;
      let sizeLimitType = "text";

      if (ATTACHMENT_CONFIG.IMAGE_EXTENSIONS.has(ext)) {
        maxBytes = Number.isFinite(imageMaxBytes) && imageMaxBytes > 0
          ? imageMaxBytes
          : ATTACHMENT_CONFIG.IMAGE_MAX_BYTES;
        sizeLimitType = "image";
      } else if (ATTACHMENT_CONFIG.STRUCTURED_TEXT_EXTENSIONS.has(ext)) {
        maxBytes = Number.isFinite(structuredTextMaxBytes) && structuredTextMaxBytes > 0
          ? structuredTextMaxBytes
          : ATTACHMENT_CONFIG.STRUCTURED_TEXT_MAX_BYTES;
        sizeLimitType = "structured";
      }

      if (stat.size <= 0 || stat.size > maxBytes) {
        this.debugLog("Attachment text extraction skipped due to size limits", {
          name: attachment.name || path.basename(attachment.path),
          ext,
          size_limit_type: sizeLimitType,
          size_bytes: stat.size,
          max_bytes: maxBytes
        });
        return null;
      }

      const buffer = await fs.promises.readFile(attachment.path);
      return this.fromBuffer(buffer, ext, attachment.name || path.basename(attachment.path));
    } catch (_error) {
      this.debugLog("Attachment text extraction failed", {
        name: attachment.name || null,
        path: attachment.path || null
      });
      return null;
    }
  }

  /**
   * Extract from buffer with detected type
   */
  async fromBuffer(buffer, detectedType, sourceName = null) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) return null;

    if (!isSupportedExtractionType(detectedType)) {
      this.debugLog("Attachment text extraction skipped due to unsupported detected type", {
        name: sourceName,
        ext: detectedType
      });
      return null;
    }

    const text = await this.extractStructured(buffer, detectedType);
    if (text) {
      this.debugLog("Attachment text extracted via structured parser", {
        name: sourceName,
        ext: detectedType,
        extracted_chars: text.length
      });
      return text;
    }

    // Fallback for images: just return null if no structured extraction
    if (ATTACHMENT_CONFIG.IMAGE_EXTENSIONS.has(detectedType)) {
      this.debugLog("Attachment text extraction ended without text for image", {
        name: sourceName,
        ext: detectedType
      });
      return null;
    }

    // Fallback for text extensions
    if (ATTACHMENT_CONFIG.TEXT_EXTENSIONS.has(detectedType)) {
      const normalized = trimExtractedText(sanitizeExtractedText(buffer.toString("utf8")));
      if (normalized) {
        this.debugLog("Attachment text extracted via UTF-8 text decode", {
          name: sourceName,
          ext: detectedType,
          extracted_chars: normalized.length
        });
      }
      return normalized || null;
    }

    // Fallback for PDF: extract printable strings
    if (detectedType === "pdf") {
      const printable = trimExtractedText(sanitizeExtractedText(this.extractPrintableStrings(buffer)));
      return printable || null;
    }

    this.debugLog("Attachment text extraction found no usable text", {
      name: sourceName,
      ext: detectedType
    });
    return null;
  }

  /**
   * Format-specific structured text extraction
   */
  async extractStructured(buffer, format) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) return null;

    const fmt = lower(format);

    // PDF extraction
    if (fmt === "pdf") {
      return this.extractPdfText(buffer);
    }

    // DOCX extraction
    if (fmt === "docx") {
      return this.extractDocxText(buffer);
    }

    // XLSX extraction
    if (fmt === "xlsx") {
      return this.extractXlsxText(buffer);
    }

    // PPTX extraction
    if (fmt === "pptx") {
      return this.extractPptxText(buffer);
    }

    // Image extraction (LLM OCR)
    if (ATTACHMENT_CONFIG.IMAGE_EXTENSIONS.has(fmt)) {
      return this.extractImageTextWithLlm(fmt, buffer);
    }

    return null;
  }

  /**
   * Extract text from PDF
   */
  async extractPdfText(buffer) {
    try {
      const parser = new PDFParse({ data: buffer });
      const parsed = await parser.getText();
      const normalized = trimExtractedText(sanitizeExtractedText(parsed?.text || ""));
      return normalized || null;
    } catch (_error) {
      return null;
    }
  }

  /**
   * Extract text from DOCX using mammoth
   */
  async extractDocxText(buffer) {
    try {
      const parsed = await mammoth.extractRawText({ buffer });
      const normalized = trimExtractedText(sanitizeExtractedText(parsed?.value || ""));
      return normalized || null;
    } catch (_error) {
      return null;
    }
  }

  /**
   * Extract text from XLSX - all cell values with sheet separation
   */
  async extractXlsxText(buffer) {
    try {
      const workbook = xlsx.read(buffer, { type: "buffer" });
      const sheets = [];

      for (const sheetName of workbook.SheetNames) {
        const worksheet = workbook.Sheets[sheetName];
        const csv = xlsx.utils.sheet_to_csv(worksheet);
        if (csv.trim()) {
          sheets.push(`Sheet: ${sheetName}\n${csv}`);
        }
      }

      if (sheets.length === 0) return null;
      const combined = sheets.join("\n---\n");
      return trimExtractedText(sanitizeExtractedText(combined)) || null;
    } catch (_error) {
      return null;
    }
  }

  /**
   * Extract text from PPTX - all slide text with slide numbers
   */
  async extractPptxText(buffer) {
    try {
      return await new Promise((resolve) => {
        yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipFile) => {
          if (err || !zipFile) {
            resolve(null);
            return;
          }

          const slides = [];

          zipFile.on("entry", (entry) => {
            const fileName = entry?.fileName || "";
            if (!fileName.match(/^ppt\/slides\/slide\d+\.xml$/)) {
              zipFile.readEntry();
              return;
            }

            zipFile.openReadStream(entry, (streamError, stream) => {
              if (streamError || !stream) {
                zipFile.readEntry();
                return;
              }

              const chunks = [];

              stream.on("data", (chunk) => {
                if (Buffer.isBuffer(chunk)) chunks.push(chunk);
              });

              stream.on("error", () => {
                zipFile.readEntry();
              });

              stream.on("end", () => {
                const xml = Buffer.concat(chunks).toString("utf8");
                const textMatches = xml.match(/<a:t[^>]*>(.*?)<\/a:t>/g) || [];
                const text = textMatches
                  .map((match) => match.replace(/<a:t[^>]*>|<\/a:t>/g, ""))
                  .map((value) => value
                    .replace(/&amp;/g, "&")
                    .replace(/&lt;/g, "<")
                    .replace(/&gt;/g, ">")
                    .replace(/&quot;/g, '"')
                    .replace(/&#39;/g, "'"))
                  .filter((t) => t.trim())
                  .join(" ");

                if (text) {
                  const slideMatch = fileName.match(/slide(\d+)\.xml$/);
                  const slideNumber = slideMatch ? Number(slideMatch[1]) : slides.length + 1;
                  slides.push({ slideNumber, text });
                }

                zipFile.readEntry();
              });
            });
          });

          zipFile.on("end", () => {
            if (slides.length === 0) {
              resolve(null);
              return;
            }

            slides.sort((a, b) => a.slideNumber - b.slideNumber);
            const combined = slides.map((slide) => `Slide ${slide.slideNumber}: ${slide.text}`).join("\n");
            resolve(trimExtractedText(sanitizeExtractedText(combined)) || null);
          });

          zipFile.on("error", () => {
            resolve(null);
          });

          zipFile.readEntry();
        });
      });
    } catch (_error) {
      return null;
    }
  }

  /**
   * Extract image text with LLM OCR using OpenAI Responses API
   */
  async extractImageTextWithLlm(ext, buffer) {
    const ocrEnabled = process.env.ATTACHMENT_IMAGE_OCR_WITH_LLM === "true";
    const apiKey = process.env.OPENAI_API_KEY;

    if (!ocrEnabled || !apiKey) {
      this.debugLog("Image OCR skipped due to missing config", {
        ext,
        ocr_enabled: ocrEnabled,
        has_api_key: Boolean(apiKey)
      });
      return null;
    }

    if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
      return null;
    }

    const maxBytes = Number(process.env.ATTACHMENT_IMAGE_MAX_BYTES || ATTACHMENT_CONFIG.IMAGE_MAX_BYTES);
    if (Number.isFinite(maxBytes) && maxBytes > 0 && buffer.length > maxBytes) {
      this.debugLog("Image OCR skipped due to image size limit", {
        ext,
        size_bytes: buffer.length,
        max_bytes: maxBytes
      });
      return null;
    }

    const timeoutMs = Number(process.env.ATTACHMENT_IMAGE_OCR_TIMEOUT_MS || ATTACHMENT_CONFIG.IMAGE_OCR_TIMEOUT_MS);
    const model = process.env.ATTACHMENT_IMAGE_OCR_MODEL || ATTACHMENT_CONFIG.IMAGE_OCR_MODEL;
    const baseUrl = process.env.OPENAI_BASE_URL || ATTACHMENT_CONFIG.OPENAI_BASE_URL;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : ATTACHMENT_CONFIG.IMAGE_OCR_TIMEOUT_MS);

    try {
      const base64Image = buffer.toString("base64");

      this.debugLog("Image OCR request started", {
        ext,
        size_bytes: buffer.length,
        model
      });

      const response = await global.fetch(`${baseUrl}/responses`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model,
          store: false,
          input: [
            {
              role: "user",
              content: [
                {
                  type: "input_text",
                  text: "Extract all visible text from this image. Return plain text only."
                },
                {
                  type: "input_image",
                  image_url: `data:${this.imageMimeType(ext)};base64,${base64Image}`
                }
              ]
            }
          ]
        }),
        signal: controller.signal
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "");
        this.debugLog("Image OCR request failed", {
          ext,
          status: response.status,
          error_body: errorBody
        });
        return null;
      }

      const result = await response.json();
      const extracted = this.extractResponsesApiText(result);
      const normalized = trimExtractedText(sanitizeExtractedText(extracted));

      this.debugLog("Image OCR request completed", {
        ext,
        extracted_chars: normalized.length
      });

      return normalized || null;
    } catch (_error) {
      this.debugLog("Image OCR request threw error", { ext });
      return null;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  imageMimeType(ext) {
    switch (lower(ext)) {
      case "png":
        return "image/png";
      case "jpg":
      case "jpeg":
        return "image/jpeg";
      case "webp":
        return "image/webp";
      case "gif":
        return "image/gif";
      case "bmp":
        return "image/bmp";
      case "tif":
      case "tiff":
        return "image/tiff";
      default:
        return "application/octet-stream";
    }
  }

  extractResponsesApiText(payload) {
    if (!payload || typeof payload !== "object") return "";

    if (typeof payload.output_text === "string" && payload.output_text.trim()) {
      return payload.output_text;
    }

    const outputItems = Array.isArray(payload.output) ? payload.output : [];
    const chunks = [];

    for (const item of outputItems) {
      const contentItems = Array.isArray(item?.content) ? item.content : [];
      for (const content of contentItems) {
        if (content?.type === "output_text" && typeof content.text === "string" && content.text.trim()) {
          chunks.push(content.text);
        }
      }
    }

    return chunks.join("\n");
  }

  /**
   * Helper: Check if buffer looks binary
   */
  looksBinaryBuffer(buffer) {
    return looksBinaryData(buffer);
  }

  /**
   * Helper: Extract printable strings from binary
   */
  extractPrintableStrings(buffer, minLength = 4) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) return "";
    const strings = [];
    let current = "";

    for (const byte of buffer) {
      const isPrintableAscii = byte >= 32 && byte <= 126;
      const isWhitespace = byte === 9 || byte === 10 || byte === 13;

      if (isPrintableAscii || isWhitespace) {
        current += String.fromCharCode(byte);
      } else {
        if (current.length >= minLength) {
          strings.push(current.trim());
        }
        current = "";
      }
    }

    if (current.length >= minLength) {
      strings.push(current.trim());
    }

    return strings.join("\n");
  }
}

/**
 * ArchiveInspector Class
 * Inspects and extracts text from archive files (ZIP, TAR)
 */
export class ArchiveInspector {
  constructor(debugLog = null) {
    this.debugLog = debugLog || (() => {});
    this.textExtractor = new TextExtractor(debugLog);
    this.fileTypeDetector = new FileTypeDetector(null, debugLog);
  }

  /**
   * Inspect archive metadata
   */
  async inspectMetadata(filePath, detectedType, archiveSizeBytes = 0) {
    if (!filePath || !detectedType) return null;

    const type = lower(detectedType);

    if (type === "zip") {
      return this.inspectZipArchive(filePath, archiveSizeBytes);
    }

    if (this.isTarLikeArchive(filePath, type)) {
      return this.inspectTarArchive(filePath, archiveSizeBytes);
    }

    return null;
  }

  /**
   * Extract entry texts from archive
   */
  async extractEntryTexts(filePath, detectedType) {
    if (!filePath || !detectedType) return [];

    const type = lower(detectedType);

    if (type === "zip") {
      return this.extractZipArchiveEntryTexts(filePath);
    }

    if (this.isTarLikeArchive(filePath, type)) {
      return this.extractTarArchiveEntryTexts(filePath);
    }

    return [];
  }

  /**
   * Inspect ZIP archive
   */
  async inspectZipArchive(filePath, archiveSizeBytes = 0) {
    return new Promise((resolve) => {
      yauzl.open(filePath, { lazyEntries: true, autoClose: true }, (openError, zipFile) => {
        if (openError || !zipFile) {
          resolve(null);
          return;
        }

        const fileTypes = [];
        let fileCount = 0;
        let totalCompressedBytes = 0;
        let totalUncompressedBytes = 0;
        let passwordProtected = false;

        zipFile.on("entry", async (entry) => {
          if (!(entry.fileName || "").endsWith("/")) {
            if (this.shouldIgnoreArchiveEntry(entry.fileName || "")) {
              zipFile.readEntry();
              return;
            }

            fileCount++;
            const fallbackExt = fileExtension(path.basename(entry.fileName || ""));
            if (this.isZipEntryEncrypted(entry)) {
              passwordProtected = true;
            }

            const compressedSize = Number(entry.compressedSize);
            if (Number.isFinite(compressedSize) && compressedSize >= 0) {
              totalCompressedBytes += compressedSize;
            }

            const uncompressedSize = Number(entry.uncompressedSize);
            if (Number.isFinite(uncompressedSize) && uncompressedSize >= 0) {
              totalUncompressedBytes += uncompressedSize;
            }

            const entryBuffer = await this.readZipEntrySampleBuffer(zipFile, entry, 8192);
            const actualExt = await this.detectActualExtFromBuffer(entryBuffer, fallbackExt);
            if (actualExt) fileTypes.push(actualExt);
          }

          zipFile.readEntry();
        });

        zipFile.on("end", () => {
          const denominator = archiveSizeBytes > 0
            ? archiveSizeBytes
            : (totalCompressedBytes > 0 ? totalCompressedBytes : 0);
          const compressionRatio = denominator > 0
            ? toFixedNumber(totalUncompressedBytes / denominator)
            : null;

          resolve(
            AttachmentMetadata.buildArchiveMetadata({
              containsFileTypes: fileTypes,
              fileCount,
              passwordProtected,
              compressionRatio
            })
          );
        });

        zipFile.on("error", () => {
          resolve(null);
        });

        zipFile.readEntry();
      });
    });
  }

  /**
   * Inspect TAR archive
   */
  async inspectTarArchive(filePath, archiveSizeBytes) {
    let fileCount = 0;
    let totalUncompressedBytes = 0;
    const fileTypes = [];
    const detectionTasks = [];

    try {
      await tar.t({
        file: filePath,
        onentry: (entry) => {
          if (entry.type === "File") {
            const entryName = entry.path || entry.name || "";
            if (this.shouldIgnoreArchiveEntry(entryName)) {
              entry.resume();
              return;
            }

            fileCount++;
            totalUncompressedBytes += entry.size;

            const fallbackExt = fileExtension(path.basename(entry.name || ""));
            const chunks = [];
            let total = 0;

            const task = new Promise((resolveEntry) => {
              entry.on("data", (chunk) => {
                if (!Buffer.isBuffer(chunk)) return;
                total += chunk.length;
                if (total <= 8192) {
                  chunks.push(chunk);
                }
              });

              entry.on("end", async () => {
                const entryBuffer = chunks.length > 0 ? Buffer.concat(chunks) : null;
                const actualExt = await this.detectActualExtFromBuffer(entryBuffer, fallbackExt);
                if (actualExt) fileTypes.push(actualExt);
                resolveEntry();
              });

              entry.on("error", () => {
                if (fallbackExt) fileTypes.push(fallbackExt);
                resolveEntry();
              });
            });

            detectionTasks.push(task);
          }
        }
      });

      await Promise.allSettled(detectionTasks);

      const compressionRatio =
        archiveSizeBytes > 0 ? toFixedNumber(totalUncompressedBytes / archiveSizeBytes) : null;

      return AttachmentMetadata.buildArchiveMetadata({
        containsFileTypes: fileTypes,
        fileCount,
        passwordProtected: false,
        compressionRatio
      });
    } catch (_error) {
      return null;
    }
  }

  /**
   * Extract ZIP entry texts
   */
  async extractZipArchiveEntryTexts(filePath) {
    return new Promise((resolve) => {
      yauzl.open(filePath, { lazyEntries: true, autoClose: true }, (openError, zipFile) => {
        if (openError || !zipFile) {
          resolve([]);
          return;
        }

        const entries = [];
        let inspectedFiles = 0;
        let finished = false;

        const done = () => {
          if (finished) return;
          finished = true;
          resolve(entries);
        };

        zipFile.on("error", () => done());
        zipFile.on("end", () => done());

        zipFile.on("entry", async (entry) => {
          if (!entry || /(^|\/)$/.test(entry.fileName || "")) {
            zipFile.readEntry();
            return;
          }

          if (this.shouldIgnoreArchiveEntry(entry.fileName || "")) {
            zipFile.readEntry();
            return;
          }

          if (inspectedFiles >= ATTACHMENT_CONFIG.ARCHIVE_ENTRY_MAX_FILES) {
            zipFile.readEntry();
            return;
          }

          inspectedFiles++;
          const entryName = entry.fileName;
          const entryExt = fileExtension(path.basename(entryName));
          const entryBuffer = await this.readZipEntryBuffer(zipFile, entry);

          if (entryBuffer && entryBuffer.length > 0) {
            const actualExt = await this.detectActualExtFromBuffer(entryBuffer, entryExt);
            if (!isSupportedExtractionType(actualExt)) {
              zipFile.readEntry();
              return;
            }

            const extracted = await this.textExtractor.fromBuffer(entryBuffer, actualExt, entryName);
            if (extracted) {
              entries.push({ filename: entryName, extracted_text: extracted });
            }
          }

          zipFile.readEntry();
        });

        zipFile.readEntry();
      });
    });
  }

  /**
   * Extract TAR entry texts
   */
  async extractTarArchiveEntryTexts(filePath) {
    const entries = [];
    let inspectedFiles = 0;

    try {
      await tar.t({
        file: filePath,
        onentry: (entry) => {
          if (!entry || entry.type !== "File") return;
          if (inspectedFiles >= ATTACHMENT_CONFIG.ARCHIVE_ENTRY_MAX_FILES) {
            entry.resume();
            return;
          }

          inspectedFiles++;
          const chunks = [];
          let total = 0;
          let exceeded = false;

          entry.on("data", (chunk) => {
            if (exceeded || !Buffer.isBuffer(chunk)) return;
            total += chunk.length;
            if (total > ATTACHMENT_CONFIG.ARCHIVE_ENTRY_MAX_BYTES) {
              exceeded = true;
              return;
            }
            chunks.push(chunk);
          });

          entry.on("end", async () => {
            if (exceeded) return;
            const entryBuffer = Buffer.concat(chunks);
            const entryName = entry.path || "unknown";
            const entryExt = fileExtension(path.basename(entryName));
            const actualExt = await this.detectActualExtFromBuffer(entryBuffer, entryExt);
            if (!isSupportedExtractionType(actualExt)) return;

            const extracted = await this.textExtractor.fromBuffer(entryBuffer, actualExt, entryName);
            if (extracted) {
              entries.push({ filename: entryName, extracted_text: extracted });
            }
          });
        }
      });
    } catch (_error) {
      return [];
    }

    return entries;
  }

  /**
   * Read ZIP entry as buffer
   */
  readZipEntryBuffer(zipFile, entry, maxBytes = ATTACHMENT_CONFIG.ARCHIVE_ENTRY_MAX_BYTES) {
    return new Promise((resolve) => {
      zipFile.openReadStream(entry, (streamError, stream) => {
        if (streamError || !stream) {
          resolve(null);
          return;
        }

        const chunks = [];
        let total = 0;
        let exceeded = false;

        stream.on("data", (chunk) => {
          if (exceeded || !Buffer.isBuffer(chunk)) return;
          total += chunk.length;
          if (total > maxBytes) {
            exceeded = true;
            return;
          }
          chunks.push(chunk);
        });

        stream.on("error", () => resolve(null));
        stream.on("close", () => {
          resolve(exceeded ? null : Buffer.concat(chunks));
        });
        stream.on("end", () => {
          if (!exceeded) resolve(Buffer.concat(chunks));
        });
      });
    });
  }

  readZipEntrySampleBuffer(zipFile, entry, maxBytes = 8192) {
    return new Promise((resolve) => {
      zipFile.openReadStream(entry, (streamError, stream) => {
        if (streamError || !stream) {
          resolve(null);
          return;
        }

        const chunks = [];
        let total = 0;

        stream.on("data", (chunk) => {
          if (!Buffer.isBuffer(chunk)) return;
          if (total >= maxBytes) return;

          const remaining = maxBytes - total;
          if (chunk.length <= remaining) {
            chunks.push(chunk);
            total += chunk.length;
            return;
          }

          chunks.push(chunk.subarray(0, remaining));
          total += remaining;
        });

        stream.on("error", () => resolve(null));
        stream.on("close", () => {
          resolve(chunks.length > 0 ? Buffer.concat(chunks) : null);
        });
        stream.on("end", () => {
          resolve(chunks.length > 0 ? Buffer.concat(chunks) : null);
        });
      });
    });
  }

  async detectActualExtFromBuffer(buffer, fallbackExt = "") {
    return this.fileTypeDetector.detectBestExtension(buffer, fallbackExt);
  }

  shouldIgnoreArchiveEntry(entryName = "") {
    const normalized = String(entryName || "").replace(/\\/g, "/");
    if (!normalized) return true;
    if (normalized.startsWith("__MACOSX/")) return true;
    return path.basename(normalized).startsWith("._");
  }

  isZipEntryEncrypted(entry) {
    if (!entry || typeof entry !== "object") return false;
    const flag = Number(entry.generalPurposeBitFlag);
    return Number.isFinite(flag) ? (flag & 0x1) === 0x1 : false;
  }

  /**
   * Check if archive is TAR-like
   */
  isTarLikeArchive(filePath, ext) {
    const normalizedPath = lower(filePath);
    if (ext === "tar" || ext === "tgz") return true;
    if (
      normalizedPath.endsWith(".tar.gz") ||
      normalizedPath.endsWith(".tar.bz2") ||
      normalizedPath.endsWith(".tar.xz")
    ) {
      return true;
    }
    return false;
  }
}
