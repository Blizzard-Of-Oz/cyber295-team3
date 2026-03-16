const URGENCY_PATTERNS = [
  { keyword: "URGENT", pattern: /\burgent\b/i },
  { keyword: "IMMEDIATELY", pattern: /\bimmediately\b/i },
  { keyword: "DO NOT DELAY", pattern: /\bdo\s+not\s+delay\b/i },
  { keyword: "CEO DEMANDS", pattern: /\bceo\s+demands\b/i },
  { keyword: "NOW", pattern: /\bnow\b/i }
];

function getCandidateTexts(req, args = {}, existingContext = {}) {
  const requestContext = req?.body?.context || {};
  return {
    request_body_context_userInput: requestContext.userInput,
    context_user_input: existingContext.user_input,
    context_content_text: existingContext.content_text,
    email_subject: typeof args.subject === "string" ? args.subject : "",
    email_body: typeof args.body === "string" ? args.body : ""
  };
}

export function extractUrgencySignals(req, args = {}, existingContext = {}) {
  const candidates = getCandidateTexts(req, args, existingContext);
  const matchedKeywords = new Set();

  for (const value of Object.values(candidates)) {
    if (typeof value !== "string" || !value.trim()) continue;
    for (const { keyword, pattern } of URGENCY_PATTERNS) {
      if (pattern.test(value)) {
        matchedKeywords.add(keyword);
      }
    }
  }

  const matches = [...matchedKeywords];
  const urgencyScore = matches.length;

  return {
    urgency_manipulation: urgencyScore > 0,
    urgency_signals: {
      matched_keywords: matches,
      urgency_score: urgencyScore,
      inspected_fields: Object.keys(candidates)
    }
  };
}

export function normalizeOpaDecision(payload) {
  if (!payload) {
    return {
      allow: false,
      reason: "missing_opa_response",
      decision: "DENY",
      actions: [],
      cooldownSeconds: 0,
      raw: payload
    };
  }

  if (typeof payload.result === "boolean") {
    const allow = payload.result;
    return {
      allow,
      reason: allow ? "ok" : "denied",
      decision: allow ? "ALLOW" : "DENY",
      actions: [],
      cooldownSeconds: 0,
      raw: payload
    };
  }

  if (payload.result && typeof payload.result === "object") {
    const decision = typeof payload.result.decision === "string"
      ? payload.result.decision.toUpperCase()
      : null;
    const actions = Array.isArray(payload.result.actions) ? payload.result.actions : [];
    const cooldownSeconds = Number(payload.result.cooldown_seconds) || 0;
    const explicitAllow = typeof payload.result.allow === "boolean" ? payload.result.allow : null;

    const isThrottle = decision === "THROTTLE" || actions.includes("ENFORCE_COOLDOWN") || cooldownSeconds > 0;
    const isDeny = decision === "DENY" || decision === "BLOCK";
    const allow = explicitAllow === null
      ? !(isThrottle || isDeny)
      : explicitAllow && !(isThrottle || isDeny);

    return {
      allow,
      reason: payload.result.reason || (allow ? "ok" : "denied"),
      decision: decision || (allow ? "ALLOW" : "DENY"),
      actions,
      cooldownSeconds,
      raw: payload
    };
  }

  return {
    allow: false,
    reason: "invalid_opa_response",
    decision: "DENY",
    actions: [],
    cooldownSeconds: 0,
    raw: payload
  };
}
