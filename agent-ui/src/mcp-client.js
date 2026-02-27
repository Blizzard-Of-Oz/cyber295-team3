export class McpClientManager {
  constructor() {
    this.baseUrl = process.env.MCP_HTTP_URL || "http://localhost:5001";
    this.debug = process.env.DEBUG === "true";
  }

  log(message, meta) {
    if (!this.debug) return;
    if (meta !== undefined) {
      console.log(`[agent-ui][debug] ${message}`, meta);
    } else {
      console.log(`[agent-ui][debug] ${message}`);
    }
  }

  async listTools() {
    this.log("Fetching tools", { baseUrl: this.baseUrl });
    const response = await fetch(`${this.baseUrl}/tools`);
    if (!response.ok) {
      this.log("Tools request failed", { status: response.status });
      throw new Error(`Failed to list tools: ${response.status}`);
    }
    const data = await response.json();
    this.log("Tools loaded", { count: data.tools?.length || 0 });
    return data.tools || [];
  }

  async callTool(name, args, context = {}) {
    this.log("Calling tool", { name, args });
    const headers = { "Content-Type": "application/json" };
    if (context.authenticatedUser) {
      headers["X-Authenticated-User"] = context.authenticatedUser;
    }
    if (context.entraToken) {
      headers["X-Entra-Token"] = context.entraToken;
    }
    if (context.requesterIp) {
      headers["X-User-Ip"] = context.requesterIp;
    }
    if (context.correlationId) {
      headers["X-Correlation-Id"] = context.correlationId;
    }
    const response = await fetch(`${this.baseUrl}/call-tool`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        name,
        arguments: args,
        context: {
          userInput: context.userInput || null,
          correlationId: context.correlationId || null
        }
      })
    });

    const data = await response.json();
    if (!response.ok || data?.success === false) {
      this.log("Tool call failed", { status: response.status, error: data?.error });
      const error = new Error(data?.error || `Tool call failed: ${response.status}`);
      error.reason = data?.reason || null;
      error.status = response.status;
      error.details = data || null;
      throw error;
    }
    this.log("Tool call succeeded", { name });
    return data.result;
  }
}
