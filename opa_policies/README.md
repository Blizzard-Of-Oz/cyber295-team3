# OPA Policy Folder

This folder contains the OPA policy and data files loaded by OPAL into OPA.

## Current policy contract

- **Package:** `gmail`
- **Endpoint queried by app:** `POST /v1/data/gmail/decision` (configured by `OPA_DECISION_URL` in `gmail-mcp-http`).
- **Input payload:** app sends `{ "input": ... }` where `input` includes:
  - `tool.name`, `tool.arguments`
  - `requester.identity`, `requester.ip`
  - `request.method`, `request.path`, `request.headers`, `request.body`

The policy keeps compatibility with the current app by returning:

- `data.gmail.allow` (boolean)
- `data.gmail.decision` (object containing `allow`, `reason`, `reasons`, `decision`, `risk`)

## Policy pack v2 (agentic controls)

`gmail.rego` applies controls to **send actions** only (`send_email` / `gmail_send_email`):

- blocked recipient deny
- internal domain + external allowlist enforcement
- broadcast/company-wide restriction by requester identity
- max recipients limit
- non-empty subject requirement
- max body length limit
- structured deny reasons
- optional non-breaking `REQUIRE_APPROVAL` signal in `decision.decision`

## Configuration

Edit `data.json` under the `config` object:

- `internal_domains`
- `allowed_external_emails`
- `blocked_recipients`
- `broadcast_patterns`
- `broadcast_allowed_identities`
- `max_recipients`
- `max_body_chars`
- `require_nonempty_subject`

## Run tests

From repo root:

```bash
opa test opa_policies -v
```

## Quick demos

### Allow scenario

Input: `send_email` to `alice@ischool.berkeley.edu`, non-empty subject/body, normal requester.  
Result: `allow=true`, decision `ALLOW`.

### Deny scenario

Input: `send_email` to `yaoyaozong@gmail.com`.  
Result: `allow=false`, reason like `blocked_recipient:yaoyaozong@gmail.com`.

---

## OPA Server Setup (via OPAL)

To ensure that the OPA server automatically loads the latest policies from the policy repository, we use **[Open Policy Administration Layer (OPAL)](https://docs.opal.ac)**.

1. **OPAL Server** monitors policy repo changes and pushes updates.
2. **OPAL Client** receives updates and PUTs them into OPA.

---

## Setup OPA testing environment on local 
1. Download OPA CLI
1. Run 'opa test'
1. Troubleshooting
  1. opa eval
  1. curl
