# Agent CLI Demo

Minimal guide for running the demo with the current Agent CLI flow.

## What this demo does

- Runs `scripts/agent_demo.sh` to execute policy-focused email scenarios.
- Uses natural language requests through the Agent CLI.
- Exercises MCP tools and OPA policy checks end-to-end.

## Prerequisites

In project root `.env`:

```env
OPENAI_API_KEY=your-api-key
OPENAI_MODEL=gpt-4-mini
MCP_HTTP_URL=http://localhost:5001
DEBUG=false
```

Make sure the MCP HTTP server is running on `MCP_HTTP_URL`.

## Run

From project root:

```bash
bash scripts/agent_demo.sh
```

Run one direct CLI request:

```bash
AUTHENTICATED_USER='maya@company.com' node agent-ui/src/cli.js 'Send an email to alice@company.com with subject "Test" and body "Hello"'
```

JSON output:

```bash
node agent-ui/src/cli.js --json 'your request' 2>/dev/null | jq
```

## Included scenarios (high level)

1. Routine internal status email (expected allowed)
2. Company-wide notification (expected allowed)
3. Suspicious external message pattern (expected flagged/reviewed)
4. Large sensitive data export request (expected higher scrutiny)

## Quick troubleshooting

- `OPENAI_API_KEY` errors: verify `.env` exists in project root.
- MCP connection issues: verify `MCP_HTTP_URL` and server status.
- JSON parse issues: keep `2>/dev/null | jq` for clean output.

## Note on migration

The old HTTP-style demo still exists (`scripts/demo_scenarios.sh`), but the recommended path is `scripts/agent_demo.sh`.
