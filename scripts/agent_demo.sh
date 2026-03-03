#!/usr/bin/env bash

# Agent CLI Demo Script
# This script demonstrates the agent CLI by running various email scenarios
# It tests policy enforcement through the OPA integration

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the project root directory
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_UI_DIR="${AGENT_UI_DIR:-${PROJECT_ROOT}/agent-ui}"
CLI_SCRIPT="${AGENT_UI_DIR}/src/cli.js"

# Ensure the CLI script exists
if [ ! -f "$CLI_SCRIPT" ]; then
  echo -e "${RED}Error: CLI script not found at $CLI_SCRIPT${NC}"
  exit 1
fi

# Load environment from project root .env if it exists
if [ -f "${PROJECT_ROOT}/.env" ]; then
  set -a
  source "${PROJECT_ROOT}/.env"
  set +a
fi

# Ensure we're in the agent-ui directory to run the CLI (for relative imports)
cd "$AGENT_UI_DIR"

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}Gmail Agent CLI Demo${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""

# Helper function to run a scenario
run_scenario() {
  local scenario_num="$1"
  local user="$2"
  local request_description="$3"
  local demo_timestamp="${4:-}"  # Optional 4th parameter for demo timestamp
  
  echo -e "${YELLOW}--- Scenario $scenario_num: $request_description ---${NC}"
  echo -e "${BLUE}User: $user${NC}"
  if [ -n "$demo_timestamp" ]; then
    echo -e "${BLUE}Demo Timestamp: $demo_timestamp${NC}"
  fi
  echo ""
  
  # Run the agent CLI with JSON output for easy parsing
  local response=$(AUTHENTICATED_USER="$user" DEMO_TIMESTAMP="$demo_timestamp" node "src/cli.js" --json "$request_description" 2>/dev/null)
  
  # Extract key information
  local success=$(echo "$response" | jq -r '.success')
  local summary=$(echo "$response" | jq -r '.summary')
  
  echo -e "${BLUE}Response:${NC}"
  echo "$summary"
  echo ""
  
  # Check if any tool had errors (policy denied)
  local has_errors=$(echo "$response" | jq '[.toolOutputs[] | select(.error != null)] | length > 0')
  
  if [ "$has_errors" = "true" ]; then
    echo -e "${RED}⚠️  Policy Denial Detected:${NC}"
    echo "$response" | jq -r '.toolOutputs[] | select(.error != null) | "   \(.name): \(.error.reason // .error.message)"'
  else
    echo -e "${GREEN}✓ Request Allowed${NC}"
  fi
  
  # Show tool calls that were made
  local tool_count=$(echo "$response" | jq '[.toolCalls[]] | length')
  if [ "$tool_count" -gt 0 ]; then
    echo -e "${BLUE}Tools Called ($tool_count):${NC}"
    echo "$response" | jq -r '.toolCalls[] | "  - \(.name): \(.arguments | tostring)"'
  fi
  
  echo ""
  echo "---"
  echo ""
}

# Scenario 1: Routine incident status update (should be allowed)
run_scenario 1 "team3@billyyaoischoolberkeley.onmicrosoft.com" \
  "Send an email to alice@billyyaoischoolberkeley.onmicrosoft.com and bob@billyyaoischoolberkeley.onmicrosoft.com with subject 'Incident status update' and body 'Routine incident status update'"

# Scenario 2: Company-wide notification (should be rejected by OPA policy due to mass email)
run_scenario 2 "maya@billyyaoischoolberkeley.onmicrosoft.com" \
  "Send an email with subject 'FYI' and body 'Company-wide notification' to all employees group (all-employees@billyyaoischoolberkeley.onmicrosoft.com)"


echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}Demo Complete${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""
echo -e "${YELLOW}To run individual scenarios:${NC}"
echo "  AUTHENTICATED_USER='user@billyyaoischoolberkeley.onmicrosoft.com' node agent-ui/src/cli.js 'your request'"
echo ""
echo -e "${YELLOW}With demo timestamp (for business hours testing):${NC}"
echo "  AUTHENTICATED_USER='user@billyyaoischoolberkeley.onmicrosoft.com' DEMO_TIMESTAMP='2026-03-11T16:00:00.000Z' node agent-ui/src/cli.js 'your request'"
echo ""
echo -e "${YELLOW}For JSON output (machine-readable):${NC}"
echo "  node agent-ui/src/cli.js --json 'your request' 2>/dev/null | jq"
echo ""
