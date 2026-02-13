import { OpenAI } from "openai";
import crypto from "crypto";

export function createAgent({ mcpClientManager }) {
  const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  const model = process.env.OPENAI_MODEL || "gpt-4.1-mini";
  const DEBUG = process.env.DEBUG === "true";

  const debugLog = (message, meta) => {
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
  };

  async function run(requirement, context = {}) {
    if (!openai.apiKey) {
      throw new Error("OPENAI_API_KEY is not set");
    }

    const correlationId = crypto.randomBytes(12).toString("hex");
    context = { ...context, correlationId };

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
      { role: "system", content: systemPrompt },
      { role: "user", content: requirement }
    ];

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
