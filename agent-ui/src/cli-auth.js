import * as msal from "@azure/msal-node";
import http from "http";
import url from "url";
import open from "open";

const DEBUG = process.env.DEBUG === "true";

function debugLog(message, meta) {
  if (!DEBUG) return;
  console.error("\n---");
  if (meta !== undefined) {
    try {
      console.error(`[agent-cli][auth-debug] ${message}`, JSON.stringify(meta, null, 2));
    } catch {
      console.error(`[agent-cli][auth-debug] ${message}`, meta);
    }
  } else {
    console.error(`[agent-cli][auth-debug] ${message}`);
  }
  console.error("---\n");
}

/**
 * Creates MSAL configuration for CLI
 */
function getMsalConfig() {
  if (!process.env.AZURE_CLIENT_ID || !process.env.AZURE_TENANT_ID) {
    throw new Error(
      "Azure configuration missing. Set AZURE_CLIENT_ID and AZURE_TENANT_ID."
    );
  }

  return {
    auth: {
      clientId: process.env.AZURE_CLIENT_ID,
      authority: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}`,
      clientSecret: process.env.AZURE_CLIENT_SECRET || undefined
    },
    system: {
      loggerOptions: {
        loggerCallback(_loglevel, message, containsPii) {
          if (containsPii) return;
          if (DEBUG) {
            console.error(`[agent-cli][msal] ${message}`);
          }
        },
        piiLoggingEnabled: false,
        logLevel: msal.LogLevel.Warning
      }
    }
  };
}

/**
 * Browser-based authentication flow
 * Starts a local server to catch the redirect, prints auth URL for user to open
 */
export async function authenticateWithBrowser() {
  return new Promise(async (resolve, reject) => {
    // Find available port
    const server = http.createServer();
    let port = 3301;
    
    server.listen(0, "localhost", async () => {
      port = server.address().port;
      const redirectUri = `http://localhost:${port}/auth/callback`;
      
      try {
        const msalConfig = getMsalConfig();
        const msalInstance = new msal.PublicClientApplication(msalConfig);

        const authCodeUrlParameters = {
          scopes: ["user.read"],
          redirectUri
        };

        debugLog("Starting browser auth flow", { redirectUri });
        const authCodeUrl = await msalInstance.getAuthCodeUrl(authCodeUrlParameters);

        // Handle callback
        server.on("request", async (req, res) => {
          const parseUrl = url.parse(req.url || "", true);

          if (parseUrl.pathname === "/auth/callback") {
            const authCode = parseUrl.query.code;
            const error = parseUrl.query.error;
            const errorDescription = parseUrl.query.error_description;

            if (error) {
              debugLog("Auth error", { error, errorDescription });
              res.writeHead(400, { "Content-Type": "text/html" });
              res.end(`<h1>Authentication Error</h1><p>${error}: ${errorDescription}</p>`);
              server.close();
              reject(new Error(`${error}: ${errorDescription}`));
              return;
            }

            if (!authCode) {
              res.writeHead(400, { "Content-Type": "text/html" });
              res.end("<h1>Missing authorization code</h1>");
              server.close();
              reject(new Error("Missing authorization code"));
              return;
            }

            // Success response
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(
              "<h1>Authentication Successful</h1><p>You can close this window and return to your terminal.</p>"
            );

            // Exchange code for token
            try {
              const tokenRequest = {
                code: authCode,
                scopes: ["user.read"],
                redirectUri
              };

              debugLog("Acquiring token", { code: authCode?.substring(0, 20) + "..." });
              const response = await msalInstance.acquireTokenByCode(tokenRequest);
              
              debugLog("Token acquired successfully");
              server.close();
              resolve({
                accessToken: response.accessToken,
                account: response.account,
                user: response.account?.username || "authenticated-user"
              });
            } catch (tokenError) {
              debugLog("Token acquisition failed", { error: tokenError?.message });
              server.close();
              reject(tokenError);
            }
          }
        });

        // Print instructions to user
        console.log("\n📝 Opening browser for authentication...\n");
        console.log("If browser doesn't open, copy and paste this URL:\n");
        console.log(`  ${authCodeUrl}\n`);
        console.log("Waiting for authentication...\n");

        // Try to open browser
        try {
          await open(authCodeUrl);
        } catch (e) {
          debugLog("Could not auto-open browser", { error: e?.message });
          // Continue anyway - user can manually copy-paste
        }
      } catch (error) {
        server.close();
        reject(error);
      }
    });

    server.on("error", reject);
  });
}

/**
 * Device code authentication flow
 * User gets a code to enter on device.microsoft.com
 */
export async function authenticateWithDeviceCode() {
  try {
    const msalConfig = getMsalConfig();
    const msalInstance = new msal.PublicClientApplication(msalConfig);

    if (!msalInstance.acquireTokenByDeviceCode) {
      throw new Error(
        "Device code flow not supported. Ensure MSAL is properly configured."
      );
    }

    debugLog("Starting device code auth flow");

    const deviceCodeRequest = {
      scopes: ["user.read"],
      deviceCodeCallback: (response) => {
        console.log("\n🔐 Device Code Flow\n");
        console.log("1. Visit: https://microsoft.com/devicelogin");
        console.log(`2. Enter this code: ${response.userCode}\n`);
        console.log("Waiting for authentication...\n");
      }
    };

    const response = await msalInstance.acquireTokenByDeviceCode(deviceCodeRequest);

    debugLog("Device code auth successful");
    return {
      accessToken: response.accessToken,
      account: response.account,
      user: response.account?.username || "authenticated-user"
    };
  } catch (error) {
    debugLog("Device code auth failed", { error: error?.message });
    throw error;
  }
}

/**
 * Get authenticated user info
 */
export function getAuthenticatedUser(result) {
  return {
    user: result?.user || result?.account?.username || "authenticated-user",
    token: result?.accessToken
  };
}
