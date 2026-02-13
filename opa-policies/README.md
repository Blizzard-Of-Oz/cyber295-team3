# OPA Policy Folder

This folder contains the policy files (`.rego`) that are loaded into the OPA server.

The OPA server evaluates incoming requests and makes authorization decisions based on the policies defined in this directory.

---

## OPA Server Setup (via OPAL)

To ensure that the OPA server automatically loads the latest policies from the policy repository, we use **[Open Policy Administration Layer (OPAL)](https://docs.opal.ac)**

### How It Works

1. **OPAL Server**
   - Monitors the policy repository for changes.
   - Detects updates (e.g., new commits or modifications to `.rego` files).
   - Fetches the latest version of the policies when changes are detected.
   - Pushes the updated policies to the OPAL Client.

2. **OPAL Client**
   - Receives policy updates from the OPAL Server.
   - Pushes (PUTs) the updated policies into the OPA server.

This setup ensures that the OPA server always runs the most up-to-date policies without requiring manual reloads.
