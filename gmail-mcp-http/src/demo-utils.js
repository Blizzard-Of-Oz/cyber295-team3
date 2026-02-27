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
