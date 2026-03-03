#!/usr/bin/env bash
set -euo pipefail

WRAPPER_URL="${WRAPPER_URL:-http://localhost:5001}"

run() {
  local id="$1"
  echo "\n=== Running Scenario ${id} ==="
  curl -sS -X POST "${WRAPPER_URL}/demo/scenarios/${id}" \
    -H 'content-type: application/json' | jq .
}

run 1
run 2
run 3
run 4

echo "\nTry lock behavior (should be denied as account locked):"
curl -sS -X POST "${WRAPPER_URL}/call-tool" \
  -H 'content-type: application/json' \
  -d '{"name":"send_email","authenticatedUser":"marcus@company.com","arguments":{"to":["alice@company.com"],"subject":"test","body":"test"}}' | jq .
