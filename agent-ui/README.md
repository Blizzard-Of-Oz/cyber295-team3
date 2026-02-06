# Gmail Agent UI

This service provides a simple web UI and an orchestration agent that calls the OpenAI API and then invokes the Gmail MCP HTTP wrapper.

## Prerequisites

- Node.js 18+
- Gmail MCP server built locally
- Gmail MCP HTTP wrapper running
- OpenAI API key

## Setup

1. Build the Gmail MCP server (submodule):

```
cd mcp-server/gmail
npm install
npm run build
```

2. Install and run the Gmail MCP HTTP wrapper:

```
cd gmail-mcp-http
npm install
npm run dev
```

3. Install dependencies for the agent server:

```
cd agent-ui
npm install
```

4. Set environment variables:

```
export OPENAI_API_KEY=your_key_here
export OPENAI_MODEL=gpt-4.1-mini
```

Optional overrides:

```
export MCP_HTTP_URL=http://localhost:3301
export DEBUG=true
```

## Run

```
npm run dev
```

Open http://localhost:3300 in your browser.

## Notes

- Ensure Gmail OAuth credentials exist as described in the Gmail MCP server README.
- The MCP server is launched via stdio by the agent process.
