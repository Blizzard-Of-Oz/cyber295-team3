const URGENCY_PATTERNS = [
  { keyword: "URGENT", pattern: /\burgent\b/i },
  { keyword: "IMMEDIATELY", pattern: /\bimmediately\b/i },
  { keyword: "DO NOT DELAY", pattern: /\bdo\s+not\s+delay\b/i },
  { keyword: "CEO DEMANDS", pattern: /\bceo\s+demands\b/i },
  { keyword: "NOW", pattern: /\bnow\b/i }
];

function toTrimmedString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function toRecipientList(args = {}, existingContext = {}) {
  if (Array.isArray(existingContext.recipients)) {
    return existingContext.recipients.filter((value) => typeof value === "string" && value.trim());
  }

  const recipients = [];
  const candidateFields = [args.to, args.cc, args.bcc, args?.message?.to];
  for (const field of candidateFields) {
    if (Array.isArray(field)) {
      for (const entry of field) {
        if (typeof entry === "string" && entry.trim()) recipients.push(entry.trim());
      }
      continue;
    }
    if (typeof field === "string" && field.trim()) {
      recipients.push(field.trim());
    }
  }
  return recipients;
}

function buildContentText(args = {}, existingContext = {}) {
  if (typeof existingContext.content_text === "string" && existingContext.content_text.length > 0) {
    return existingContext.content_text;
  }

  const subject = typeof args.subject === "string" ? args.subject : "";
  const body = typeof args.body === "string" ? args.body : "";

  if (!subject && !body) return "";
  return `${subject}\n${body}\n`;
}

function getCandidateTexts(req, args = {}, existingContext = {}) {
  const requestContext = req?.body?.context && typeof req.body.context === "object" ? req.body.context : {};
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
  return {
    urgency_manipulation: matches.length > 0,
    urgency_signals: {
      matched_keywords: matches,
      urgency_score: matches.length,
      inspected_fields: Object.keys(candidates)
    }
  };
}

export function buildOpaContext(req, args = {}) {
  const requestContext = req?.body?.context && typeof req.body.context === "object" ? req.body.context : {};
  const recipients = toRecipientList(args, requestContext);
  const baseContext = {
    recipient_count: Number(requestContext.recipient_count) || recipients.length,
    recipients,
    content_text: buildContentText(args, requestContext),
    user_input: toTrimmedString(requestContext.userInput || requestContext.user_input),
    attachment_bytes: Number(requestContext.attachment_bytes ?? requestContext.attachmentBytes) || 0,
    attachment_name: requestContext.attachment_name ?? requestContext.attachmentName ?? null,
    data_classification: requestContext.data_classification ?? requestContext.dataClassification ?? "none",
    record_count: Number(requestContext.record_count ?? requestContext.recordCount) || 0
  };

  return {
    ...baseContext,
    ...extractUrgencySignals(req, args, baseContext)
  };
}

export function buildOpaInput(req, toolName, args, helpers) {
  const requesterIp = helpers.getRequesterIp(req);
  const authenticatedUser = helpers.getAuthenticatedUser(req);
  const headers = helpers.collectOpaHeaders(req);

  return {
    tool: {
      name: toolName,
      arguments: args
    },
    requester: {
      ip: requesterIp,
      identity: authenticatedUser,
      token: headers["x-entra-token"] || headers.authorization || null
    },
    request: {
      method: req.method,
      path: req.path,
      headers,
      body: req.body || null
    },
    context: buildOpaContext(req, args)
  };
}

export function normalizeOpaDecision(payload) {
  if (payload === null || payload === undefined) {
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
    const allow = explicitAllow === null ? !(isThrottle || isDeny) : explicitAllow && !(isThrottle || isDeny);

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
