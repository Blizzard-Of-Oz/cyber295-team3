export class McpClientManager {
  constructor(options = {}) {
    this.baseUrl = process.env.MCP_HTTP_URL || "http://localhost:5001";
    this.debug = process.env.DEBUG === "true";
    this.jsonMode = options.jsonMode || false;
    this.debugLogs = options.debugLogs || null; // Array to collect debug logs
  }

  /**
   * Convert ISO timestamp to nanoseconds since epoch
   * @param {string} isoTimestamp - ISO 8601 timestamp string
   * @returns {string} - Timestamp in nanoseconds
   */
  isoToNanoseconds(isoTimestamp) {
    const date = new Date(isoTimestamp);
    const milliseconds = date.getTime();
    return String(milliseconds * 1000000); // Convert ms to ns
  }

  log(message, meta) {
    if (!this.debug) return;
    
    const logMessage = meta !== undefined 
      ? `[agent-ui][debug] ${message} ${JSON.stringify(meta)}`
      : `[agent-ui][debug] ${message}`;
    
    // Collect logs if array provided
    if (this.debugLogs) {
      this.debugLogs.push({ source: 'mcp-client', message, meta });
    }
    
    // In JSON mode, send to stderr; otherwise stdout
    if (this.jsonMode) {
      console.error(logMessage);
    } else {
      console.log(logMessage);
    }
  }

  async listTools(options = {}) {
    this.log("Fetching tools", { baseUrl: this.baseUrl });
    const response = await fetch(`${this.baseUrl}/tools`, {
      signal: options.signal
    });
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
    if (context.demoTimestamp) {
      try {
        const timestampNs = this.isoToNanoseconds(context.demoTimestamp);
        headers["x-demo-timestamp-ns"] = timestampNs;
        this.log("Using demo timestamp", { iso: context.demoTimestamp, ns: timestampNs });
      } catch (error) {
        this.log("Invalid demo timestamp format", { timestamp: context.demoTimestamp, error: error.message });
      }
    }

    const contextAttachments = Array.isArray(context.availableAttachmentMetadata)
      ? context.availableAttachmentMetadata
          .map((entry) => {
            const filePath = typeof entry?.path === "string" ? entry.path.trim() : "";
            if (!filePath) return null;
            const displayName =
              typeof entry?.displayName === "string" && entry.displayName.trim().length > 0
                ? entry.displayName.trim()
                : null;
            const displaySize = Number(entry?.displaySizeBytes);

            return {
              path: filePath,
              name: displayName,
              size_bytes: Number.isFinite(displaySize) && displaySize >= 0 ? displaySize : null
            };
          })
          .filter(Boolean)
      : [];

    let response;
    try {
      response = await fetch(`${this.baseUrl}/call-tool`, {
        method: "POST",
        headers,
        signal: context.abortSignal,
        body: JSON.stringify({
          name,
          arguments: args,
          context: {
            userInput: context.userInput || null,
            correlationId: context.correlationId || null,
            attachments: contextAttachments
          }
        })
      });
    } catch (error) {
      if (error?.name === "AbortError" || context.abortSignal?.aborted) {
        const abortError = new Error("Tool call canceled");
        abortError.name = "AbortError";
        throw abortError;
      }
      throw error;
    }

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
