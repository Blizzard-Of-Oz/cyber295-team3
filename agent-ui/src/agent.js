import { OpenAI } from "openai";

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

    let response = await openai.chat.completions.create({
      model,
      messages,
      tools,
      tool_choice: "auto"
    });

    let assistantMessage = response.choices[0]?.message;
    const toolCalls = assistantMessage?.tool_calls || [];
    const toolOutputs = [];

    if (toolCalls.length > 0) {
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
        const result = await mcpClientManager.callTool(name, args, context);
        debugLog("MCP tool result", { name, ok: true });
        toolOutputs.push({ name, result });

        messages.push({
          role: "tool",
          tool_call_id: call.id,
          content: JSON.stringify(result)
        });
      }

      response = await openai.chat.completions.create({
        model,
        messages
      });

      assistantMessage = response.choices[0]?.message;
    }

    return {
      summary: assistantMessage?.content || "",
      toolCalls: toolCalls.map((call) => ({
        name: call.function?.name,
        arguments: call.function?.arguments || "{}"
      })),
      toolOutputs
    };
  }

  return { run };
}
