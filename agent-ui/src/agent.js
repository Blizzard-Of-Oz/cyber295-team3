import { OpenAI } from "openai";
import crypto from "crypto";

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

    const systemPrompt = [
      "You are an orchestration agent for Gmail operations.",
      "Use the provided tools to take actions when needed.",
      "If an email should be sent, draft, labeled, searched, or read, call the appropriate tool.",
      "Be precise with recipients, subjects, and contents.",
      "If data is missing, ask a concise follow-up question instead of guessing."
    ].join(" ");

    const messages = [
      { role: "system", content: systemPrompt }
    ];

    // Inject RAG context if available
    if (ragContext) {
      messages.push({
        role: "system",
        content: `Retrieved knowledge base context:\n\n${ragContext}\n\nUse this context to inform your responses when relevant. If the context conflicts with the user request, prioritize the user's explicit instructions.`
      });
    }

    messages.push({ role: "user", content: requirement });

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
        debugLog("Calling MCP tool", { name });
        try {
          const result = await mcpClientManager.callTool(name, args, context);
          debugLog("MCP tool result", { name, ok: true });
          toolOutputs.push({ name, result });
          allToolCalls.push({ name, arguments: call.function?.arguments || "{}" });

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
          allToolCalls.push({ name, arguments: call.function?.arguments || "{}" });
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
