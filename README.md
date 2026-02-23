# Demo Project for Team 3

## AI Bot for Gmail Mailbox Management

This project is an AI-powered bot designed to help manage a Gmail mailbox.

It is built on top of the **Gmail MCP Server**:  
https://github.com/fldc/Gmail-MCP-Server.git, which is a fork from
https://github.com/GongRzhe/Gmail-MCP-Server

## Architecture Overview

- **MCP Server Base**
  The core functionality comes from the Gmail MCP Server.
- **HTTP Wrapper**
  - Exposes MCP capabilities via HTTP APIs
  - Writes audit logs to immuDB
  - Enforces OPA policy through `POST /v1/data/gmail/decision`
- **OPA policy package (`opa-policies`)**
  - Returns compatible `allow` + `reason`
  - Also returns enriched metadata: `decision`, `reasons`, `risk`, `actions`, `cooldown_seconds`, `triggered_controls`
- **Web UI / AI Agent / MCP Client**
  - Interactive UI
  - Agent orchestration for tool use

## Demo Story Runner (SOC Analyst scenarios)

Run all 4 demo scenarios against the wrapper:

```bash
scripts/demo_scenarios.sh
```

The script calls `POST /demo/scenarios/:id` and exercises:
1. **Scenario 1** ALLOW: internal team email in working hours.
2. **Scenario 2** DENY: company-wide send denied for `soc_analyst`.
3. **Scenario 3** DENY + ALERT: urgency + prompt injection + external exfil indicators.
4. **Scenario 4** DENY + ALERT + LOCK: after-hours bulk confidential export by departing employee.

After scenario 4, a follow-up request for `marcus@company.com` is denied as **account locked** until reset.

Reset a locked account (demo):

```bash
curl -X POST http://localhost:5001/demo/reset-lock/marcus@company.com
```

## OPA policy config

Policy configuration is centralized in:

- `opa-policies/data.json`

Edit this file to tune:
- business hours
- role recipient limits
- broadcast patterns + allowed roles
- urgency/injection settings
- personal domains / exfil controls
- demo user profile map

## Audit & alerts in log viewer

Use the log viewer to inspect:
- policy decisions (`mcp_policy_decisions` or `mcp-policy:`)
- actions (`mcp_actions` or `mcp-action:`)
- alerts (`mcp_alerts` or `mcp-alert:`)

Each policy decision records request ID, decision, reasons, triggered controls, and policy version.

## OPA tests (Docker)

```bash
docker run --rm -v "$PWD:/work" -w /work openpolicyagent/opa:latest test opa-policies -v
```

This includes one test per demo scenario.
