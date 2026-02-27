import express from "express";
import { scenarioPayload } from "./demo-scenarios.js";

/**
 * Create a demo router for development and testing scenarios
 * @param {number} port - The port the main server is running on
 * @param {AccountLockManager} accountLockManager - Manager for locked accounts
 * @returns {express.Router} - Configured demo router
 */
export function createDemoRouter(port, accountLockManager) {
  const router = express.Router();

  /**
   * POST /demo/scenarios/:id
   * Execute a pre-defined demo scenario
   */
  router.post("/demo/scenarios/:id", async (req, res) => {
    const payload = scenarioPayload(req.params.id);
    if (!payload) {
      return res.status(404).json({ error: "Unknown scenario" });
    }

    try {
      // Extract headers from payload (if any) and merge with content-type
      const customHeaders = payload.headers || {};
      const requestHeaders = {
        "content-type": "application/json",
        ...customHeaders
      };

      // Remove headers from payload body to avoid sending them twice
      const { headers: _, ...bodyPayload } = payload;

      const response = await fetch(`http://127.0.0.1:${port}/call-tool`, {
        method: "POST",
        headers: requestHeaders,
        body: JSON.stringify(bodyPayload)
      });
      const body = await response.json().catch(() => ({ error: "invalid_response" }));
      return res.status(response.status).json(body);
    } catch (error) {
      return res.status(500).json({ error: error?.message || "Failed to execute scenario" });
    }
  });

  /**
   * POST /demo/reset-lock/:identity
   * Reset account lock for a given identity (demo only)
   */
  router.post("/demo/reset-lock/:identity", (req, res) => {
    const identity = req.params.identity || "";
    const wasLocked = accountLockManager.unlock(identity);
    res.json({ ok: true, identity, wasLocked });
  });

  return router;
}
