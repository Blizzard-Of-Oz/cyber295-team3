import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Load demo user profiles from demo-users.json
 * Returns empty object if file doesn't exist
 */
export function loadDemoUsers() {
  const demoUsersPath = path.resolve(__dirname, "demo-users.json");
  try {
    const data = fs.readFileSync(demoUsersPath, "utf8");
    return JSON.parse(data);
  } catch (_error) {
    return {};
  }
}

/**
 * Manages demo request counter for generating sequential request IDs
 */
export class DemoRequestIdGenerator {
  constructor() {
    this.counter = 0;
  }

  nextId() {
    this.counter += 1;
    return `Request #${String(this.counter).padStart(3, "0")}`;
  }
}

/**
 * Manages locked accounts for security lockouts
 */
export class AccountLockManager {
  constructor() {
    this.lockedAccounts = new Map();
  }

  isLocked(identity) {
    return this.lockedAccounts.has((identity || "unknown").toLowerCase());
  }

  lockAccount(identity, details = {}) {
    this.lockedAccounts.set((identity || "unknown").toLowerCase(), {
      ...details,
      timestamp: new Date().toISOString()
    });
  }

  unlock(identity) {
    const key = (identity || "unknown").toLowerCase();
    const wasLocked = this.lockedAccounts.has(key);
    this.lockedAccounts.delete(key);
    return wasLocked;
  }

  getLockedAccounts() {
    return this.lockedAccounts;
  }
}
