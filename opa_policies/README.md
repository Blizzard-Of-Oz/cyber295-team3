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

## Setup OPA Testing Environment (Local)

### 1. Download OPA CLI

The current OPA server version in use is **OPA 1.9.0**.

``` bash
$ opa version
Version: 1.9.0
Build Commit: c49e670294e45bb3fd76b9e945cf821478a4bbfc
Build Timestamp: 2025-09-26T08:53:51Z
Go Version: go1.25.1
Platform: linux/amd64
Rego Version: v1
WebAssembly: unavailable
```

To avoid compatibility issues, it is recommended to use **OPA CLI
v1.9.0** locally for testing.

Download OPA v1.9.0 from:\
https://github.com/open-policy-agent/opa/releases/tag/v1.9.0

Make sure to download the binary that matches your local architecture.

#### Example: macOS (Apple Silicon)

``` bash
curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v1.9.0/opa_darwin_arm64_static
chmod +x ./opa
./opa version
```

Ensure the `opa` binary is available in your `$PATH`.\
Alternatively, place it in the root of the repository and invoke it with
`./opa`.

------------------------------------------------------------------------

### 2. Run `opa test`

Unit tests are located under:

    opa_policies/tests/

See the [Run Tests](#run-tests) section for additional details.

Run:

``` bash
./opa test opa_policies -v
```

Example output:

``` bash
opa_policies/tests/gmail_test.rego:
data.gmail_test.test_non_send_action_is_not_blocked: PASS
data.gmail_test.test_allow_internal_team_email: PASS
data.gmail_test.test_allow_broadcast_for_privileged_requester: PASS
data.gmail_test.test_allow_whitelisted_external_email: PASS
data.gmail_test.test_deny_blocked_specific_recipient: PASS
data.gmail_test.test_deny_broadcast_for_non_privileged_requester: PASS
data.gmail_test.test_deny_external_recipient_not_allowed: PASS
data.gmail_test.test_deny_empty_subject_when_required: PASS
data.gmail_test.test_deny_bulk_recipients_over_limit: PASS
--------------------------------------------------------------------------------
PASS: 9/9
```

Whenever a `.rego` file is modified, ensure all tests pass before
committing changes.

If you introduce a new use case in a `.rego` policy file, you must also
add corresponding test cases in the `*_test.rego` file.

------------------------------------------------------------------------

### 3. Troubleshooting

#### 3.1 Using `opa eval`

In addition to `opa test`, you can use `opa eval` to manually evaluate
policy decisions.

From inside the `opa_policies` folder:

##### Step 1 --- Generate test input

``` bash
cat <<'EOF' > input.json
{
  "tool": {
    "name": "send_email",
    "arguments": {
      "to": ["someone@gmail.com"],
      "subject": "zzz",
      "body": "aaaaa"
    }
  },
  "requester": {
    "ip": "1.2.3.4",
    "identity": "someone@ischool.berkeley.edu"
  },
  "request": {
    "method": "POST",
    "path": "/call-tool",
    "headers": {
      "x-authenticated-user": "someone@ischool.berkeley.edu",
      "x-user-ip": "1.2.3.4",
      "x-correlation-id": "1234567890",
      "user-agent": "node"
    },
    "body": {
      "name": "send_email",
      "arguments": {
        "to": ["someone@gmail.com"],
        "subject": "zzz",
        "body": "aaaaa"
      }
    }
  }
}
EOF
```

##### Step 2 --- Evaluate `data.gmail.allow` query path

``` bash
../opa eval -i input.json -d gmail.rego -d data.json data.gmail.allow
```

Example output:

``` bash
{
  "result": [
    {
      "expressions": [
        {
          "value": false,
          "text": "data.gmail.allow",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}
```

##### Step 3 --- Evaluate `data.gmail.decision` query path

``` bash
../opa eval -i input.json -d gmail.rego -d data.json data.gmail.decision
```

Example output:

``` bash
{
  "result": [
    {
      "expressions": [
        {
          "value": {
            "allow": false,
            "decision": "DENY",
            "reason": "blocked_recipient:someone@gmail.com",
            "reasons": [
              "blocked_recipient:someone@gmail.com",
              "external_recipient_not_allowed:someone@gmail.com"
            ],
            "risk": "high"
          },
          "text": "data.gmail.decision",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}
```

------------------------------------------------------------------------

### 4. Testing via `curl`
(TBD)

