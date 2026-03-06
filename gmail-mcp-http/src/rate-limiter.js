import { createClient } from "redis";

/**
 * Rate limiter using Redis with multi-dimensional rate limiting.
 * Supports rate limiting by identity, IP, user-agent, and custom scopes.
 * Uses fixed window rate limiting with TTL-based expiration.
 */
export class RateLimiter {
  constructor(config) {
    this.enabled = config.enabled !== false;
    this.client = null;
    this.limits = config.limits || {}; // { "identity:action": { count, window }, "ip:action": {...} }
    this.defaultLimits = config.defaultLimits || {}; // { "identity": {...}, "ip": {...} }
    this.redisHost = config.host || "localhost";
    this.redisPort = config.port || 6379;
    this.redisUsername = config.username || null;
    this.redisPassword = config.password || null;
    this.connecting = null;
    this.debug = config.debug || false;
  }

  debugLog(message, meta) {
    if (!this.debug) return;
    if (meta !== undefined) {
      console.log(`[RateLimiter][debug] ${message}`, meta);
    } else {
      console.log(`[RateLimiter][debug] ${message}`);
    }
  }

  async connect() {
    if (!this.enabled) return;
    if (this.client?.isOpen) return;
    if (this.connecting) return this.connecting;

    this.connecting = (async () => {
      this.debugLog("Connecting to Redis", {
        host: this.redisHost,
        port: this.redisPort
      });

      const clientConfig = {
        socket: {
          host: this.redisHost,
          port: this.redisPort
        }
      };

      // Redis ACL authentication (Redis 6.0+)
      if (this.redisUsername) {
        clientConfig.username = this.redisUsername;
      }
      if (this.redisPassword) {
        clientConfig.password = this.redisPassword;
      }

      this.client = createClient(clientConfig);

      this.client.on("error", (err) => {
        console.error("[RateLimiter] Redis error:", err);
      });

      await this.client.connect();
      this.debugLog("Connected to Redis successfully");
    })();

    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  /**
   * Check if a request is allowed under the rate limit for a specific scope.
   * @param {string} scope - Rate limit scope (e.g., "identity", "ip", "useragent")
   * @param {string} value - Scope value (e.g., "user@example.com", "192.168.1.1")
   * @param {string} action - Action name (tool name, e.g., "send_email")
   * @param {boolean} incrementCounter - Whether to increment the counter (default: true)
   * @returns {Promise<{allowed: boolean, scope?: string, reason?: string, limit?: number, window?: number, resetIn?: number, remaining?: number}>}
   */
  async checkLimit(scope, value, action, incrementCounter = true) {
    if (!this.enabled) {
      return { allowed: true, reason: "rate_limiting_disabled" };
    }

    try {
      await this.connect();
    } catch (error) {
      console.error("[RateLimiter] Failed to connect to Redis:", error);
      // Fail open - allow request if Redis connection fails
      return { allowed: true, reason: "rate_limiter_unavailable", error: error.message };
    }

    // Normalize action name to match env variable format
    const normalizedAction = action.replace(/-/g, "_").toLowerCase();
    const normalizedScope = scope.toLowerCase();
    
    // Look for specific limit: scope_action (e.g., "identity_send_email")
    const scopeActionKey = `${normalizedScope}_${normalizedAction}`;
    let limit = this.limits[scopeActionKey];
    
    // Fall back to scope default (e.g., "identity" default)
    if (!limit) {
      limit = this.defaultLimits[normalizedScope];
    }

    if (!limit) {
      this.debugLog("No limit configured for scope+action", { scope: normalizedScope, action: normalizedAction });
      return { allowed: true, reason: "no_limit_configured" };
    }

    const key = `ratelimit:${normalizedScope}:${value}:${normalizedAction}`;
    this.debugLog("Checking rate limit", { key, limit, incrementCounter });

    try {
      const current = await this.client.get(key);
      const count = current ? parseInt(current, 10) : 0;

      this.debugLog("Current count", { key, count, limit: limit.count });

      if (count >= limit.count) {
        const ttl = await this.client.ttl(key);
        this.debugLog("Rate limit exceeded", { key, count, limit: limit.count, ttl });
        return {
          allowed: false,
          scope: normalizedScope,
          reason: `rate_limit_exceeded_${normalizedScope}`,
          limit: limit.count,
          window: limit.window,
          resetIn: ttl > 0 ? ttl : limit.window,
          current: count
        };
      }

      // Only increment counter if requested (for multi-scope checks)
      if (incrementCounter) {
        if (count === 0) {
          // First request in window, set with TTL
          await this.client.setEx(key, limit.window, "1");
          this.debugLog("Started new rate limit window", { key, window: limit.window });
        } else {
          // Increment existing counter
          await this.client.incr(key);
          this.debugLog("Incremented rate limit counter", { key, newCount: count + 1 });
        }
      }

      return {
        allowed: true,
        scope: normalizedScope,
        remaining: limit.count - count - 1,
        limit: limit.count,
        window: limit.window,
        key: key // Include key for incrementing later
      };
    } catch (error) {
      console.error("[RateLimiter] Error checking limit:", error);
      // Fail open - allow request if Redis operation fails
      return { allowed: true, reason: "rate_limiter_error", error: error.message };
    }
  }

  /**
   * Check multiple rate limit scopes at once.
   * @param {Array<{scope: string, value: string}>} checks - Array of scope checks
   * @param {string} action - Action name
   * @returns {Promise<{allowed: boolean, results: Array, violated?: object}>}
   */
  async checkMultiple(checks, action) {
    // Phase 1: Check all limits WITHOUT incrementing counters
    const results = await Promise.all(
      checks.map(({ scope, value }) => this.checkLimit(scope, value, action, false))
    );

    // Check if any scope is violated
    const violated = results.find(r => !r.allowed && r.reason && r.reason.startsWith("rate_limit_exceeded"));
    
    if (violated) {
      // At least one limit exceeded, deny request without incrementing any counters
      this.debugLog("Multi-scope check denied", { violated });
      return {
        allowed: false,
        results,
        violated
      };
    }

    // Phase 2: All checks passed, now increment all counters
    try {
      await Promise.all(
        results.map(async (result) => {
          // Only increment if this result has a configured limit
          if (result.key && result.limit && result.window) {
            try {
              const current = await this.client.get(result.key);
              const count = current ? parseInt(current, 10) : 0;
              
              this.debugLog("Incrementing counter", { key: result.key, currentCount: count, limit: result.limit });
              
              if (count === 0) {
                // First request in window, set with TTL
                await this.client.setEx(result.key, result.window, "1");
                this.debugLog("Started new rate limit window (phase2)", { key: result.key, window: result.window, setTo: 1 });
              } else {
                // Increment existing counter
                const newCount = await this.client.incr(result.key);
                this.debugLog("Incremented rate limit counter (phase2)", { key: result.key, newCount });
              }
            } catch (err) {
              console.error("[RateLimiter] Error incrementing counter for key", result.key, ":", err);
            }
          }
        })
      );
    } catch (error) {
      console.error("[RateLimiter] Error incrementing counters in multi-check:", error);
      // Counters may be partially incremented, but request was allowed
    }
    
    return {
      allowed: true,
      results,
      violated: null
    };
  }

  /**
   * Reset rate limit for a specific scope, value, and action (useful for testing/admin operations)
   */
  async resetLimit(scope, value, action) {
    if (!this.enabled) return;

    try {
      await this.connect();
      const normalizedAction = action.replace(/-/g, "_").toLowerCase();
      const normalizedScope = scope.toLowerCase();
      const key = `ratelimit:${normalizedScope}:${value}:${normalizedAction}`;
      await this.client.del(key);
      this.debugLog("Reset rate limit", { key });
    } catch (error) {
      console.error("[RateLimiter] Error resetting limit:", error);
    }
  }

  /**
   * Get current rate limit status for a scope, value, and action
   */
  async getStatus(scope, value, action) {
    if (!this.enabled) {
      return { enabled: false };
    }

    try {
      await this.connect();
      const normalizedAction = action.replace(/-/g, "_").toLowerCase();
      const normalizedScope = scope.toLowerCase();
      
      const scopeActionKey = `${normalizedScope}_${normalizedAction}`;
      const limit = this.limits[scopeActionKey] || this.defaultLimits[normalizedScope];

      if (!limit) {
        return { enabled: true, configured: false };
      }

      const key = `ratelimit:${normalizedScope}:${value}:${normalizedAction}`;
      const current = await this.client.get(key);
      const count = current ? parseInt(current, 10) : 0;
      const ttl = count > 0 ? await this.client.ttl(key) : -1;

      return {
        enabled: true,
        configured: true,
        scope: normalizedScope,
        value,
        action: normalizedAction,
        limit: limit.count,
        window: limit.window,
        current: count,
        remaining: Math.max(0, limit.count - count),
        resetIn: ttl > 0 ? ttl : null
      };
    } catch (error) {
      console.error("[RateLimiter] Error getting status:", error);
      return { enabled: true, error: error.message };
    }
  }

  async close() {
    if (this.client?.isOpen) {
      await this.client.quit();
      this.debugLog("Disconnected from Redis");
    }
  }
}

/**
 * Parse rate limit configuration from environment variables.
 * 
 * Expected format:
 * - RATE_LIMIT_ENABLED=true|false (default: true)
 * - RATE_LIMIT_{SCOPE}_DEFAULT=count:window (e.g., RATE_LIMIT_IDENTITY_DEFAULT=20:60)
 * - RATE_LIMIT_{SCOPE}_{ACTION}=count:window (e.g., RATE_LIMIT_IDENTITY_SEND_EMAIL=3:60)
 * 
 * Supported scopes: IDENTITY, IP, USERAGENT, or custom
 * 
 * Examples:
 * - RATE_LIMIT_IDENTITY_DEFAULT=20:60 - Default limit for all actions by identity
 * - RATE_LIMIT_IDENTITY_SEND_EMAIL=3:60 - Specific limit for send_email by identity
 * - RATE_LIMIT_IP_DEFAULT=100:60 - Default limit for all actions by IP
 * - RATE_LIMIT_IP_SEND_EMAIL=10:60 - Specific limit for send_email by IP
 * 
 * @param {object} env - Environment variables object (process.env)
 * @returns {object} Configuration object for RateLimiter
 */
export function parseRateLimitConfig(env) {
  const enabled = env.RATE_LIMIT_ENABLED !== "false";
  const limits = {}; // Specific scope+action limits
  const defaultLimits = {}; // Default limits per scope

  // Parse all RATE_LIMIT_* variables
  for (const [key, value] of Object.entries(env)) {
    if (
      key.startsWith("RATE_LIMIT_") &&
      key !== "RATE_LIMIT_ENABLED"
    ) {
      const parts = key.replace("RATE_LIMIT_", "").toLowerCase().split("_");
      
      if (parts.length < 2) continue;
      
      const scope = parts[0]; // e.g., "identity", "ip", "useragent"
      const rest = parts.slice(1).join("_"); // e.g., "default" or "send_email"
      
      try {
        const limitValue = parseRateLimitValue(value);
        
        if (rest === "default") {
          // This is a default limit for the scope
          defaultLimits[scope] = limitValue;
        } else {
          // This is a specific scope+action limit
          const scopeActionKey = `${scope}_${rest}`;
          limits[scopeActionKey] = limitValue;
        }
      } catch (error) {
        console.error(`[RateLimiter] Invalid ${key}:`, error.message);
      }
    }
  }

  return {
    enabled,
    host: env.REDIS_HOST || "localhost",
    port: env.REDIS_PORT ? parseInt(env.REDIS_PORT, 10) : 6379,
    username: env.REDIS_USERNAME || null,
    password: env.REDIS_PASSWORD || null,
    limits,
    defaultLimits,
    debug: env.DEBUG === "true"
  };
}

/**
 * Parse a rate limit value string.
 * @param {string} value - Format: "count:window" e.g., "3:60"
 * @returns {{count: number, window: number}}
 */
function parseRateLimitValue(value) {
  const [count, window] = value.split(":").map((v) => parseInt(v, 10));
  if (isNaN(count) || isNaN(window) || count <= 0 || window <= 0) {
    throw new Error(`Invalid rate limit format: ${value}. Expected "count:window" (e.g., "3:60")`);
  }
  return { count, window };
}
