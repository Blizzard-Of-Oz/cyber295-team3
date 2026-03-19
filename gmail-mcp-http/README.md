# Gmail MCP HTTP Wrapper

This service wraps the Gmail MCP stdio server and exposes HTTP endpoints, while writing action logs to immuDB.

## Endpoints

- GET /health
- GET /tools
- POST /call-tool

### Attachment Context for Policy

For `send_email` and `draft_email`, the wrapper now normalizes attachment inputs and enriches OPA context:

- Accepts `attachments` (array of file paths), `attachmentPath`, or `attachment_path`
- Enforces an attachment sandbox: all paths must be inside `ATTACHMENT_SANDBOX_ROOT`
- Computes `context.attachment_bytes` from existing local files when explicit byte values are not provided
- Sets `context.attachment_name` from attachment filenames when not explicitly provided
- Adds `context.attachment_count`

This prevents attachment fields from remaining `0`/`null` when file-path attachments are supplied.
It also blocks local file inclusion from arbitrary host paths.

## Setup

1. Build the Gmail MCP server:

```
git submodule update --init --recursive

cd mcp-server/gmail
npm install
npm run build
```

2. Install dependencies for this wrapper:

```
cd gmail-mcp-http
npm install
```

3. Configure environment variables:

```
# Required for MCP stdio
MCP_COMMAND=node
MCP_ARGS=/absolute/path/to/mcp-server/gmail/dist/index.js

# HTTP
MCP_HTTP_PORT=3301
DEBUG=false

# Attachment sandbox (defaults to AGENT_UPLOAD_TEMP_DIR, then /tmp/agent-ui-attachments)
ATTACHMENT_SANDBOX_ROOT=/tmp/agent-ui-attachments

# OPA
OPA_ENABLED=true
OPA_DECISION_URL=http://localhost:8181/v1/data/gmail/decision
OPA_TIMEOUT_MS=2000
OPA_FAIL_OPEN=false

# immuDB (optional)
IMMUDB_ENABLED=true
IMMUDB_HOST=127.0.0.1
IMMUDB_PORT=3322
IMMUDB_USER=immudb
IMMUDB_PASSWORD=immudb
IMMUDB_DATABASE=defaultdb
IMMUDB_MODE=kv
```

4. Run:

```
npm run dev
```

5. Server Deployment
```
sudo npm install -g pm2
npm install -g pm2

pm2 start src/index.js --name "mcp-server"
pm2 start web/server.js --name "web-server" --env web/.env



pm2 list
pm2 logs
pm2 delete 1
pm2 restart all

pm2 save
pm2 startup

sudo systemctl restart pm2-yao.service 

pm2 flush
sudo systemctl restart pm2-yao.service 
```

## OPA Policy

The policy is in the opa_policies/