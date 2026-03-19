import { OpenAI } from "openai";
import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import os from "os";

export function createAgent({ mcpClientManager, jsonMode = false, debugLogs = null }) {
  const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  const model = process.env.OPENAI_MODEL || "gpt-4.1-mini";
  const DEBUG = process.env.DEBUG === "true";

  const debugLog = (message, meta) => {
    if (!DEBUG) return;
    
    // Collect logs if array provided
    if (debugLogs) {
      debugLogs.push({ source: 'agent', message, meta });
    }
    
    // In JSON mode, send to stderr; otherwise stdout
    const output = jsonMode ? console.error : console.log;
    output("\n---");
    if (meta !== undefined) {
      try {
        output(`[agent-ui][debug] ${message}`, JSON.stringify(meta, null, 2));
      } catch {
        output(`[agent-ui][debug] ${message}`, meta);
      }
    } else {
      output(`[agent-ui][debug] ${message}`);
    }
    output("---");
  };

  function normalizeAttachmentMetadata(context) {
    if (!Array.isArray(context?.availableAttachmentMetadata)) return [];
    return context.availableAttachmentMetadata
      .map((entry) => {
        const path = typeof entry?.path === "string" ? entry.path.trim() : "";
        if (!path) return null;
        const displayName =
          typeof entry?.displayName === "string" && entry.displayName.trim().length > 0
            ? entry.displayName.trim()
            : path;
        const size = Number(entry?.displaySizeBytes);
        return {
          path,
          displayName,
          displaySizeBytes: Number.isFinite(size) && size >= 0 ? size : 0
        };
      })
      .filter(Boolean);
  }

  function applyAttachmentOpaOverrides(args, attachmentMetadata) {
    if (!Array.isArray(attachmentMetadata) || attachmentMetadata.length === 0) return;
    const names = attachmentMetadata.map((entry) => entry.displayName).filter(Boolean);
    const totalBytes = attachmentMetadata.reduce(
      (sum, entry) => sum + Number(entry.displaySizeBytes || 0),
      0
    );

    if (args.attachmentName === undefined && args.attachment_name === undefined && names.length > 0) {
      args.attachmentName = names.join(",");
    }
    if (args.attachmentBytes === undefined && args.attachment_bytes === undefined) {
      args.attachmentBytes = totalBytes;
    }
  }

  function uniqueAttachmentPaths(values) {
    if (!Array.isArray(values)) return [];
    return [...new Set(values.filter((v) => typeof v === "string" && v.trim().length > 0).map((v) => v.trim()))];
  }

  function resolveAttachmentPathAliases(attachments, availableAttachmentPaths, availableAttachmentMetadata) {
    const available = uniqueAttachmentPaths(availableAttachmentPaths);
    const byAlias = new Map();

    for (const fullPath of available) {
      byAlias.set(fullPath.toLowerCase(), fullPath);
      const baseName = fullPath.split(/[\\/]/).pop();
      if (baseName) byAlias.set(baseName.toLowerCase(), fullPath);
    }

    for (const meta of availableAttachmentMetadata || []) {
      const fullPath = typeof meta?.path === "string" ? meta.path.trim() : "";
      if (!fullPath) continue;
      const displayName = typeof meta?.displayName === "string" ? meta.displayName.trim() : "";
      if (displayName) byAlias.set(displayName.toLowerCase(), fullPath);
    }

    const requested = Array.isArray(attachments)
      ? attachments
      : typeof attachments === "string"
        ? [attachments]
        : [];

    const resolved = [];
    for (const item of requested) {
      if (typeof item !== "string") continue;
      const key = item.trim().toLowerCase();
      if (!key) continue;
      const resolvedPath = byAlias.get(key);
      if (resolvedPath) resolved.push(resolvedPath);
    }

    return uniqueAttachmentPaths(resolved);
  }

  function sanitizeGeneratedAttachmentName(name) {
    if (typeof name !== "string") return "generated.txt";
    const normalized = path.basename(name).replace(/[^a-zA-Z0-9._-]/g, "_");
    return normalized || "generated.txt";
  }

  async function createGeneratedAttachmentFile(args, context, availableAttachmentPaths, availableAttachmentMetadata) {
    const content = typeof args?.content === "string" ? args.content : "";
    const requestedName = typeof args?.filename === "string" ? args.filename : "generated.txt";
    const baseName = sanitizeGeneratedAttachmentName(requestedName);
    const rootDir =
      typeof context?.generatedAttachmentDir === "string" && context.generatedAttachmentDir.trim().length > 0
        ? context.generatedAttachmentDir
        : process.env.AGENT_UPLOAD_TEMP_DIR ||
          path.join(os.tmpdir(), "agent-ui-attachments");

    await fs.mkdir(rootDir, { recursive: true });

    const extension = path.extname(baseName);
    const stem = extension ? baseName.slice(0, -extension.length) : baseName;
    let candidate = baseName;
    let counter = 1;
    while (availableAttachmentPaths.includes(path.join(rootDir, candidate))) {
      candidate = `${stem}-${counter}${extension}`;
      counter += 1;
    }

    const filePath = path.join(rootDir, candidate);
    await fs.writeFile(filePath, content, "utf8");

    const byteSize = Buffer.byteLength(content, "utf8");
    availableAttachmentPaths.push(filePath);
    availableAttachmentMetadata.push({
      path: filePath,
      displayName: candidate,
      displaySizeBytes: byteSize
    });

    return {
      path: filePath,
      filename: candidate,
      sizeBytes: byteSize,
      message: `Generated attachment created at ${filePath}`
    };
  }

  async function run(requirement, context = {}) {
    if (!openai.apiKey) {
      throw new Error("OPENAI_API_KEY is not set");
    }

    const correlationId = crypto.randomBytes(12).toString("hex");
    context = { ...context, correlationId, userInput: requirement };

    // RAG: Retrieve relevant context from vector store
    const vectorStoreId = process.env.OPENAI_VECTOR_STORE_ID;
    const topK = Number(process.env.RAG_TOP_K || 5);
    const minScore = Number(process.env.RAG_MIN_SCORE || 0.6);
    
    let ragContext = "";
    if (vectorStoreId) {
      debugLog("RAG retrieval started", { vectorStoreId, topK, minScore });
      try {
        // Query the vector store
        const searchRes = await openai.vectorStores.search(vectorStoreId, {
          query: requirement,
          max_num_results: topK
        });

        // Filter by similarity score and format results
        const hits = (searchRes?.data || [])
          .filter((h) => (h.score ?? 0) >= minScore)
          .map((h, i) => {
            // Extract text content from the chunk
            const text = (h.content || [])
              .map((c) => c.text?.value || c.text || "")
              .join("\n")
              .slice(0, 1500); // Limit each chunk to 1500 chars
            const source = h.metadata?.filename || h.file_id || `doc_${i + 1}`;
            return `[Source #${i + 1}: ${source}]\n${text}`;
          });

        if (hits.length > 0) {
          ragContext = hits.join("\n\n");
          debugLog("RAG retrieval successful", { chunks: hits.length });
        } else {
          debugLog("RAG retrieval: no chunks met score threshold", { minScore });
        }
      } catch (error) {
        debugLog("RAG retrieval failed; continuing without context", { 
          error: error?.message,
          status: error?.status 
        });
      }
    }

    const mcpTools = await mcpClientManager.listTools();
    debugLog("Tools loaded for agent", { count: mcpTools.length });
    const tools = mcpTools.map((tool) => ({
      type: "function",
      function: {
        name: tool.name,
        description: tool.description || "",
        parameters: tool.inputSchema || { type: "object", properties: {} }
      }
    }));
    tools.push({
      type: "function",
      function: {
        name: "create_text_attachment",
        description:
          "Create a UTF-8 text file attachment from generated content and return the local file path. " +
          "Use this before send_email/draft_email when the user asks for AI-generated content as an attachment.",
        parameters: {
          type: "object",
          properties: {
            filename: {
              type: "string",
              description: "Desired filename, for example summary.txt or ticket-report.md"
            },
            content: {
              type: "string",
              description: "Text content to write into the attachment file"
            }
          },
          required: ["filename", "content"],
          additionalProperties: false
        }
      }
    });

    const systemPrompt = [
      "You are an AI agent specialized in handling Gmail operations and IT ticket management.",
      "",
      "IMPORTANT: Ticket Information Sources:",
      "- When the user asks about IT TICKETS, issues, problems, or incidents: Use the knowledge base context provided below.",
      "- When the user explicitly asks to SEARCH EMAILS or check Gmail: Use the email search and read tools.",
      "- Do NOT search emails for ticket information - always use the provided knowledge base context for tickets.",
      "",
      "Guidelines:",
      "1. If the user mentions 'tickets', 'issues', 'incidents', 'problems', or 'support requests': Refer to the knowledge base context.",
      "2. If the user explicitly says 'search emails', 'check inbox', 'find in Gmail', or 'email search': Use email tools.",
      "3. Be precise with recipients, subjects, and email contents when sending emails.",
      "3a. For send_email and draft_email, always use the `attachments` field as an array of local file paths when attachments are requested.",
      "3b. If the user asks for generated content to be attached as a file, first call `create_text_attachment`, then include its returned path in `attachments` for send_email or draft_email.",
      "4. If the user asks something not covered in the knowledge base and clarifies it's about emails, then search emails.",
      "5. If data is missing and ambiguous, ask for clarification rather than guessing."
    ].join(" ");

    const messages = [
      { role: "system", content: systemPrompt }
    ];

    // Inject RAG context with clear instructions about its purpose
    if (ragContext) {
      messages.push({
        role: "system",
        content: `KNOWLEDGE BASE - IT TICKETS DATABASE:\n\nUse the following ticket information to answer user questions about tickets, issues, or incidents:\n\n${ragContext}\n\nThis is your authoritative source for ticket information. If the user asks about ticket details, solutions, or ticket-related actions (like emailing ticket summaries), always pull from this context first. Do not search emails for this information.`
      });
    } else {
      messages.push({
        role: "system",
        content: `NOTE: No knowledge base context is currently available. If the user asks about tickets, let them know the knowledge base is unavailable. For email-related requests, use the email search and read tools.`
      });
    }

    messages.push({ role: "user", content: requirement });

    const availableAttachmentPaths = Array.isArray(context.availableAttachmentPaths)
      ? context.availableAttachmentPaths.filter((v) => typeof v === "string" && v.trim().length > 0)
      : [];
    if (availableAttachmentPaths.length > 0) {
      messages.push({
        role: "system",
        content:
          "Attachment context: The following local files are pre-approved and available on the agent host for this request. " +
          "If the user asks to send/draft with attachment(s), pass these exact file paths in send_email/draft_email `attachments`. " +
          `Available paths: ${availableAttachmentPaths.join(", ")}`
      });
    }

    const availableAttachmentMetadata = normalizeAttachmentMetadata(context);
    if (availableAttachmentMetadata.length > 0) {
      const details = availableAttachmentMetadata
        .map((entry) => `${entry.path} [displayName=${entry.displayName}; displaySizeBytes=${entry.displaySizeBytes}]`)
        .join(" | ");
      messages.push({
        role: "system",
        content:
          "Attachment demo metadata: when sending/drafting emails with attachments, include OPA policy fields " +
          "`attachmentName` and `attachmentBytes` using these display values (not filesystem size). " +
          `Metadata: ${details}`
      });
    }

    const toolOutputs = [];
    const allToolCalls = [];
    let assistantMessage = null;
    let response = null;
    let stepsRemaining = 7;

    while (stepsRemaining > 0) {
      response = await openai.chat.completions.create({
        model,
        messages,
        tools,
        tool_choice: "auto"
      });

      assistantMessage = response.choices[0]?.message;
      const toolCalls = assistantMessage?.tool_calls || [];

      if (toolCalls.length === 0) {
        break;
      }

      debugLog("Tool calls returned", toolCalls.map((call) => ({
        name: call.function?.name,
        id: call.id
      })));

      messages.push({
        role: "assistant",
        content: assistantMessage.content || "",
        tool_calls: toolCalls
      });

      for (const call of toolCalls) {
        const name = call.function?.name;
        const args = call.function?.arguments
          ? JSON.parse(call.function.arguments)
          : {};

        if (name === "create_text_attachment") {
          debugLog("Creating generated text attachment", {
            filename: args?.filename,
            contentLength: typeof args?.content === "string" ? args.content.length : 0
          });
          try {
            const result = await createGeneratedAttachmentFile(
              args,
              context,
              availableAttachmentPaths,
              availableAttachmentMetadata
            );
            toolOutputs.push({ name, result });
            allToolCalls.push({ name, arguments: JSON.stringify(args) });
            messages.push({
              role: "tool",
              tool_call_id: call.id,
              content: JSON.stringify(result)
            });
          } catch (error) {
            const errorInfo = {
              message: error?.message || "Failed to create generated attachment",
              reason: null,
              status: null,
              details: null
            };
            debugLog("Generated attachment creation failed", { error: errorInfo });
            toolOutputs.push({ name, error: errorInfo });
            allToolCalls.push({ name, arguments: JSON.stringify(args) });
            messages.push({
              role: "tool",
              tool_call_id: call.id,
              content: JSON.stringify({ error: errorInfo.message })
            });
          }
          continue;
        }

        // Always propagate uploaded WebUI attachments for send/draft tools so they are not dropped.
        if (
          (name === "send_email" || name === "draft_email") &&
          availableAttachmentPaths.length > 0
        ) {
          const resolvedRequested = resolveAttachmentPathAliases(
            args.attachments,
            availableAttachmentPaths,
            availableAttachmentMetadata
          );
          args.attachments = uniqueAttachmentPaths([
            ...resolvedRequested,
            ...availableAttachmentPaths
          ]);
          debugLog("Expanded attachments for email action", {
            name,
            attachmentCount: args.attachments.length
          });
        }

        if (name === "send_email" || name === "draft_email") {
          const metadataByPath = new Map(
            availableAttachmentMetadata.map((entry) => [entry.path, entry])
          );
          const attachedPaths = Array.isArray(args.attachments)
            ? args.attachments.filter((v) => typeof v === "string" && v.trim().length > 0)
            : [];
          const attachedMetadata = attachedPaths
            .map((p) => metadataByPath.get(p))
            .filter(Boolean);
          applyAttachmentOpaOverrides(args, attachedMetadata);
        }

        debugLog("Calling MCP tool", { name });
        try {
          const result = await mcpClientManager.callTool(name, args, context);
          debugLog("MCP tool result", { name, ok: true });
          toolOutputs.push({ name, result });
          allToolCalls.push({ name, arguments: JSON.stringify(args) });

          messages.push({
            role: "tool",
            tool_call_id: call.id,
            content: JSON.stringify(result)
          });
        } catch (error) {
          const errorInfo = {
            message: error?.message || "Tool call failed",
            reason: error?.reason || null,
            status: error?.status || null,
            details: error?.details || null
          };
          debugLog("MCP tool denied or failed", { name, error: errorInfo });
          toolOutputs.push({ name, error: errorInfo });
          allToolCalls.push({ name, arguments: JSON.stringify(args) });
          const denialSummary = errorInfo.reason
            ? `Request denied by policy: ${errorInfo.reason}`
            : errorInfo.message;
          return {
            summary: denialSummary,
            toolCalls: allToolCalls,
            toolOutputs
          };
        }
      }

      stepsRemaining -= 1;
    }

    return {
      summary: assistantMessage?.content || "",
      toolCalls: allToolCalls,
      toolOutputs
    };
  }

  return { run };
}
