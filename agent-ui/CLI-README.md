# Gmail Agent CLI

A command-line interface for the Gmail Agent, allowing you to interact with Gmail through natural language requests without using the web UI.

## Setup

1. **Environment variables**: Ensure your `.env` file is configured with:
   ```
   OPENAI_API_KEY=your-openai-api-key
   OPENAI_MODEL=gpt-4-mini  # or another model you prefer
   MCP_HTTP_URL=http://localhost:5001  # URL to your MCP HTTP server
   DEBUG=false  # Set to 'true' for verbose debug output
   ```

2. **Dependencies**: Install them if you haven't already:
   ```bash
   npm install
   ```

3. **MCP Server**: Ensure your MCP HTTP server is running on the configured URL (default: `http://localhost:5001`)

## Usage

### Interactive Mode (Default)
Start the CLI without arguments to enter interactive mode:
```bash
npm run cli:interactive
```

This starts a conversation where you can make multiple requests:
```
🤖 Gmail Agent CLI - Interactive Mode
=====================================
Enter your requests below (type 'exit' to quit)

You: send an email to john@example.com about the meeting
⏳ Processing your request...
🤖 Agent Response:
---
I've sent an email to john@example.com with a message about the meeting.
---

📋 Tool Calls (1):
  1. send_email
     Args: {...}

You: exit
Goodbye! 👋
```

### Single Command Mode
Pass your request as a command-line argument:
```bash
npm run cli "send an email to alice@example.com saying I'll be late to the meeting"
```

Or use the global command if installed:
```bash
gmail-agent-cli "search for emails from my manager"
```

### JSON Output Mode (for jq parsing)
Use the `--json` or `-j` flag to get machine-readable JSON output:
```bash
# Recommended: call node directly
node src/cli.js --json "get my latest email"

# With npm, use --silent to suppress npm's own output
npm --silent run cli -- --json "search for emails from john@example.com"

# Or use the convenience script
npm --silent run cli:json "your request here"
```

**Important:** When using JSON mode, always suppress stderr with `2>/dev/null` when piping to jq to filter out debug logs:
```bash
node src/cli.js --json "your request" 2>/dev/null | jq
```

The JSON output format is:
```json
{
  "success": true,
  "userInput": "get my latest email",
  "summary": "I found your latest email...",
  "toolCalls": [
    {
      "name": "search_emails",
      "arguments": { "maxResults": 1 }
    }
  ],
  "toolOutputs": [
    {
      "name": "search_emails",
      "error": null,
      "result": { /* tool result data */ }
    }
  ],
  "debug": [ /* included only when DEBUG=true */ ]
}
```

**Debug logs in JSON:** When both `--json` and `DEBUG=true` are set, debug logs are captured in a `debug` field within the JSON output:
```bash
DEBUG=true node src/cli.js --json "test" 2>/dev/null | jq '.debug'
```

**Parse with jq:**
```bash
# Extract just the summary
node src/cli.js --json "get my latest email" 2>/dev/null | jq '.summary'

# Get the list of tool calls
node src/cli.js -j "send email to alice@example.com" 2>/dev/null | jq '.toolCalls[].name'

# Extract specific data from results
node src/cli.js --json "search emails" 2>/dev/null | jq '.toolOutputs[0].result'

# Check if the request was successful
node src/cli.js --json "your request" 2>/dev/null | jq '.success'

# Get error message if failed
node src/cli.js --json "your request" 2>/dev/null | jq 'if .success then "OK" else .error end'

# With npm (use --silent)
npm --silent run cli -- --json "search emails" 2>/dev/null | jq '.summary'
```

## Examples

### Send an Email
```bash
npm run cli "Send an email to sarah@company.com with subject 'Project Update' and body 'The project is on track'"
```

### Search Emails
```bash
npm run cli "Find all emails from john@example.com from the last week"
```

### Label Emails
```bash
npm run cli "Label all important emails with the Important label"
```

### Read Recent Emails
```bash
npm run cli "Show me my 5 most recent emails"
```

## Output

The CLI displays:
- **Agent Response**: The natural language response from the agent
- **Tool Calls**: List of Gmail operations that were performed
- **Tool Outputs**: Results from each tool call (truncated for readability)

## Debug Mode

Enable verbose logging:
```bash
DEBUG=true npm run cli "your request here"
```

This will show detailed information about:
- Tool loading
- MCP server communications
- OpenAI API calls
- Agent decision-making process

**With JSON mode:** Debug logs are sent to stderr (keeping stdout clean for JSON) and also captured in a `debug` field in the JSON output:
```bash
# See debug logs on stderr while piping JSON to jq
DEBUG=true node src/cli.js --json "your request" | jq '.summary'

# Or access debug info from within the JSON
DEBUG=true node src/cli.js --json "your request" 2>/dev/null | jq '.debug'

# Suppress all debug output (stderr) and only see JSON
DEBUG=true node src/cli.js --json "your request" 2>/dev/null | jq '.'
```

## Notes

- The CLI reuses the same agent logic as the web UI (`agent.js`)
- It connects to the same MCP HTTP server
- Authentication can be controlled via the `AUTHENTICATED_USER` environment variable
- Each request gets a unique correlation ID for tracking

## Quick jq Reference

Here are common patterns for parsing JSON output (always include `2>/dev/null` when piping to jq):

| What you want | jq command |
|---------------|------------|
| Agent's response text | `jq '.summary'` |
| Check if successful | `jq '.success'` |
| List all tools called | `jq '.toolCalls[].name'` |
| Get tool arguments | `jq '.toolCalls[].arguments'` |
| Get first tool's result | `jq '.toolOutputs[0].result'` |
| Check for errors | `jq '.toolOutputs[] \| select(.error != null)'` |
| Get debug logs (if DEBUG=true) | `jq '.debug'` |
| Pretty print everything | `jq '.'` |
| Compact output | `jq -c '.'` |
| Raw text (no quotes) | `jq -r '.summary'` |

**Example workflows:**
```bash
# Save response to variable
RESPONSE=$(node src/cli.js -j "get latest email" 2>/dev/null)
echo "$RESPONSE" | jq '.summary'

# Chain multiple jq operations
node src/cli.js -j "search emails" 2>/dev/null | jq '.toolOutputs[0].result' | jq '.emails[].subject'

# Extract and format specific fields
node src/cli.js -j "get emails" 2>/dev/null | jq -r '.toolOutputs[0].result.emails[] | "\(.from): \(.subject)"'

# Count results
node src/cli.js -j "search emails" 2>/dev/null | jq '.toolOutputs[0].result.emails | length'

# Access debug info when DEBUG=true
DEBUG=true node src/cli.js -j "test" 2>/dev/null | jq '.debug[] | select(.source == "agent")'
```

