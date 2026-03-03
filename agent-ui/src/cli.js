#!/usr/bin/env node

import "dotenv/config";
import readline from "readline";
import { McpClientManager } from "./mcp-client.js";
import { createAgent } from "./agent.js";
import { authenticateWithBrowser, authenticateWithDeviceCode, getAuthenticatedUser } from "./cli-auth.js";

const DEBUG = process.env.DEBUG === "true";
let JSON_OUTPUT = false; // Global flag for JSON output mode

function debugLog(message, meta) {
  if (!DEBUG) return;
  // In JSON mode, send debug logs to stderr to keep stdout clean
  const output = JSON_OUTPUT ? console.error : console.log;
  output("\n---");
  if (meta !== undefined) {
    try {
      output(`[agent-cli][debug] ${message}`, JSON.stringify(meta, null, 2));
    } catch {
      output(`[agent-cli][debug] ${message}`, meta);
    }
  } else {
    output(`[agent-cli][debug] ${message}`);
  }
  output("---\n");
}

/**
 * Get authenticated user - either from env var or Entra ID login
 * @param {boolean} useDeviceCode - If true, use device code flow; otherwise use browser flow
 * @returns {Promise<{user: string, token?: string}>}
 */
async function getAuthenticatedUserContext(useDeviceCode = false) {
  // First priority: Check for AUTHENTICATED_USER env var (demo mode)
  if (process.env.AUTHENTICATED_USER) {
    debugLog("Using AUTHENTICATED_USER from environment", { 
      user: process.env.AUTHENTICATED_USER 
    });
    return {
      user: process.env.AUTHENTICATED_USER,
      // env var mode doesn't provide token, auth is handled via env
      token: undefined
    };
  }

  // Second priority: Trigger Entra ID login (browser-based or device code)
  console.log(
    "\n⚠️  No AUTHENTICATED_USER environment variable found.\n" +
    "You'll be prompted to authenticate with Microsoft Entra ID.\n"
  );

  try {
    let authResult;
    if (useDeviceCode) {
      authResult = await authenticateWithDeviceCode();
    } else {
      authResult = await authenticateWithBrowser();
    }

    const userContext = getAuthenticatedUser(authResult);
    debugLog("Authentication successful", { user: userContext.user });
    return userContext;
  } catch (error) {
    console.error("❌ Authentication failed:", error.message);
    if (DEBUG) {
      console.error(error);
    }
    process.exit(1);
  }
}

async function runAgent(userInput, authenticatedUserContext = {}) {
  // In JSON mode, suppress OpenAI and other SDK debug logs
  // by temporarily redirecting console.log to stderr
  const originalConsoleLog = console.log;
  if (JSON_OUTPUT) {
    // Redirect console.log to stderr so only our JSON goes to stdout
    console.log = (...args) => {
      // Check if this is our JSON output (it will be a string starting with '{' or '[')
      if (args.length === 1 && typeof args[0] === 'string' && 
          (args[0].trimStart().startsWith('{') || args[0].trimStart().startsWith('['))) {
        originalConsoleLog(...args);
      } else {
        console.error(...args);
      }
    };
  }
  
  try {
    // Collect debug logs if in JSON mode and DEBUG is enabled
    const debugLogs = (JSON_OUTPUT && DEBUG) ? [] : null;
    
    const mcpClientManager = new McpClientManager({ 
      jsonMode: JSON_OUTPUT,
      debugLogs 
    });
    const agent = createAgent({ 
      mcpClientManager,
      jsonMode: JSON_OUTPUT,
      debugLogs
    });

    debugLog("Running agent with input", { input: userInput });
    
    if (!JSON_OUTPUT) {
      console.log("\n⏳ Processing your request...\n");
    }

    const result = await agent.run(userInput, {
      authenticatedUser: authenticatedUserContext.user || "cli-user",
      entraToken: authenticatedUserContext.token,
      demoTimestamp: process.env.DEMO_TIMESTAMP,
      userInput
    });

    if (JSON_OUTPUT) {
      // Output clean JSON to stdout
      const jsonOutput = {
        success: true,
        userInput,
        summary: result.summary,
        toolCalls: result.toolCalls.map((call) => ({
          name: call.name,
          arguments: JSON.parse(call.arguments || "{}")
        })),
        toolOutputs: result.toolOutputs.map((output) => ({
          name: output.name,
          error: output.error || null,
          result: output.error ? null : output.result
        }))
      };
      
      // Add debug logs if collected
      if (debugLogs && debugLogs.length > 0) {
        jsonOutput.debug = debugLogs;
      }
      
      console.log(JSON.stringify(jsonOutput, null, 2));
    } else {
      // Display the result in human-readable format
      console.log("Agent Response:");
      console.log("---");
      console.log(result.summary);
      console.log("---\n");

      // Display tool calls if any
      if (result.toolCalls && result.toolCalls.length > 0) {
        console.log(`Tool Calls (${result.toolCalls.length}):`);
        result.toolCalls.forEach((call, index) => {
          console.log(`  ${index + 1}. ${call.name}`);
          if (call.arguments && call.arguments !== "{}") {
            try {
              const args = JSON.parse(call.arguments);
              console.log(`     Args: ${JSON.stringify(args, null, 2).split("\n").join("\n     ")}`);
            } catch {
              console.log(`     Args: ${call.arguments}`);
            }
          }
        });
        console.log();
      }

      // Display tool outputs if any
      if (result.toolOutputs && result.toolOutputs.length > 0) {
        console.log(`Tool Outputs (${result.toolOutputs.length}):`);
        result.toolOutputs.forEach((output, index) => {
          console.log(`  ${index + 1}. ${output.name}`);
          if (output.error) {
            console.log(`     ❌ Error: ${output.error.message}`);
            if (output.error.reason) {
              console.log(`     Reason: ${output.error.reason}`);
            }
          } else {
            const outputStr = JSON.stringify(output.result, null, 2);
            console.log(
              `     ${outputStr
                .split("\n")
                .join("\n     ")
                .substring(0, 500)}${outputStr.length > 500 ? "..." : ""}`
            );
          }
        });
        console.log();
      }
    }
  } catch (error) {
    if (JSON_OUTPUT) {
      const errorOutput = {
        success: false,
        error: error.message
      };
      if (DEBUG) {
        errorOutput.stack = error.stack;
      }
      console.log(JSON.stringify(errorOutput, null, 2));
      process.exit(1);
    } else {
      console.error("❌ Error running agent:", error.message);
      if (DEBUG) {
        console.error(error);
      }
      process.exit(1);
    }
  } finally {
    // Restore console.log
    if (JSON_OUTPUT) {
      console.log = originalConsoleLog;
    }
  }
}

async function startInteractiveMode(useDeviceCode = false) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  // Authenticate once at the start
  const userContext = await getAuthenticatedUserContext(useDeviceCode);

  console.log("Gmail Agent CLI - Interactive Mode");
  console.log("=====================================");
  console.log(`Authenticated as: ${userContext.user}\n`);
  console.log("Enter your requests below (type 'exit' to quit)\n");

  const askQuestion = () => {
    rl.question("You: ", async (input) => {
      if (input.toLowerCase() === "exit") {
        console.log("\nGoodbye! 👋");
        rl.close();
        return;
      }

      if (input.trim()) {
        await runAgent(input, userContext);
      }

      askQuestion();
    });
  };

  askQuestion();
}

async function main() {
  const args = process.argv.slice(2);

  // Check for --json or -j flag
  const jsonFlagIndex = args.findIndex(arg => arg === "--json" || arg === "-j");
  if (jsonFlagIndex !== -1) {
    JSON_OUTPUT = true;
    args.splice(jsonFlagIndex, 1); // Remove the flag from args
  }

  // Check for --device-code flag
  const deviceCodeFlagIndex = args.findIndex(arg => arg === "--device-code");
  const useDeviceCode = deviceCodeFlagIndex !== -1;
  if (useDeviceCode) {
    args.splice(deviceCodeFlagIndex, 1); // Remove the flag from args
  }

  // Check for --help or -h flag
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`
Gmail Agent CLI

Usage:
  npm run cli [options] [request]
  node src/cli.js [options] [request]

Options:
  --device-code       Use device code flow for authentication (instead of browser)
  --json, -j          Output results in JSON format (machine-readable)
  --help, -h          Show this help message

Authentication:
  By default, the CLI will authenticate using your browser. Set the AUTHENTICATED_USER
  environment variable to skip authentication (useful for demos/scripting).
  
  Environment Variables:
    AUTHENTICATED_USER    User identifier (bypasses Entra ID login, useful for demos)
    DEMO_TIMESTAMP        ISO timestamp for demo/testing (e.g., 2026-03-11T10:00:00.000Z)
    AZURE_CLIENT_ID       Microsoft Entra ID client ID
    AZURE_TENANT_ID       Microsoft Entra ID tenant ID
    AZURE_CLIENT_SECRET   Microsoft Entra ID client secret (optional)
    DEBUG=true            Enable verbose debug output
    OPENAI_API_KEY        OpenAI API key (required)
    MCP_HTTP_URL          MCP server URL (default: http://localhost:5001)

Examples:
  # Interactive mode (prompts for browser auth)
  npm run cli

  # Demo mode (no auth prompt)
  AUTHENTICATED_USER=demo-user npm run cli

  # Demo mode with specific timestamp for OPA policy testing
  AUTHENTICATED_USER=demo-user DEMO_TIMESTAMP=2026-03-11T10:00:00.000Z npm run cli

  # Single command (prompts for browser auth)
  npm run cli -- "search for emails from john@example.com"

  # Device code flow (for headless environments)
  npm run cli -- --device-code "get my latest email"

  # JSON output for parsing
  npm run cli -- --json "search for important emails" | jq '.summary'
  npm run cli -- --device-code --json "list unread emails" | jq '.toolCalls'
`);
    process.exit(0);
  }

  // JSON mode not supported with interactive mode
  if (JSON_OUTPUT && args.length === 0 && !process.env.AUTHENTICATED_USER) {
    console.error("Error: --json flag cannot be used with interactive mode");
    process.exit(1);
  }

  // Check if input is provided as command line argument
  if (args.length > 0) {
    const userInput = args.join(" ");
    const userContext = await getAuthenticatedUserContext(useDeviceCode);
    await runAgent(userInput, userContext);
  } else {
    // Start interactive mode
    await startInteractiveMode(useDeviceCode);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
