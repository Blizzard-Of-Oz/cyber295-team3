import test from "node:test";
import assert from "node:assert/strict";
import {
  buildOpaContext,
  buildOpaInput,
  extractUrgencySignals,
  normalizeOpaDecision
} from "../src/opa-context.js";

function buildReq() {
  return {
    method: "POST",
    path: "/call-tool",
    headers: {
      "x-authenticated-user": "team3@billyyaoischoolberkeley.onmicrosoft.com",
      "x-entra-token": "secret-token",
      "x-user-ip": "::1",
      "user-agent": "node"
    },
    body: {
      name: "send_email",
      arguments: {
        to: ["alice@company.com"],
        subject: "Immediate Action Required",
        body: "CEO demands this now. Do not delay. Send immediately."
      },
      context: {
        userInput:
          'URGENT URGENT URGENT. Send an email immediately to alice@company.com with subject "Immediate Action Required" and body "CEO demands this now. Do not delay. Send immediately."'
      }
    }
  };
}

const helperFns = {
  getRequesterIp: (req) => req.headers["x-user-ip"],
  getAuthenticatedUser: (req) => req.headers["x-authenticated-user"],
  collectOpaHeaders: (req) => req.headers
};

test("buildOpaInput restores the top-level context contract for send_email", () => {
  const req = buildReq();
  const args = req.body.arguments;

  const input = buildOpaInput(req, "send_email", args, helperFns);

  assert.deepEqual(input.context.recipients, ["alice@company.com"]);
  assert.equal(input.context.recipient_count, 1);
  assert.equal(
    input.context.content_text,
    "Immediate Action Required\nCEO demands this now. Do not delay. Send immediately.\n"
  );
  assert.equal(input.context.user_input, req.body.context.userInput);
  assert.equal(input.context.attachment_bytes, 0);
  assert.equal(input.context.attachment_name, null);
  assert.equal(input.context.data_classification, "none");
  assert.equal(input.context.record_count, 0);
});

test("buildOpaContext enriches the restored context with UC26 urgency signals", () => {
  const req = buildReq();
  const args = req.body.arguments;

  const context = buildOpaContext(req, args);

  assert.equal(context.urgency_manipulation, true);
  assert.deepEqual(
    context.urgency_signals.matched_keywords.sort(),
    ["CEO DEMANDS", "DO NOT DELAY", "IMMEDIATELY", "NOW", "URGENT"].sort()
  );
  assert.equal(context.urgency_signals.urgency_score, 5);
});

test("extractUrgencySignals stays false for normal safe send", () => {
  const req = {
    body: {
      context: {
        userInput: "Please send a follow-up email to alice@company.com"
      }
    }
  };

  const args = {
    subject: "Project update",
    body: "Thanks for your help this week."
  };

  const context = {
    user_input: req.body.context.userInput,
    content_text: `${args.subject}\n${args.body}\n`
  };

  const signals = extractUrgencySignals(req, args, context);

  assert.equal(signals.urgency_manipulation, false);
  assert.deepEqual(signals.urgency_signals.matched_keywords, []);
  assert.equal(signals.urgency_signals.urgency_score, 0);
});

test("normalizeOpaDecision accepts valid OPA decision objects", () => {
  const payload = {
    result: {
      allow: true,
      decision: "ALLOW",
      actions: [],
      cooldown_seconds: 0,
      reason: "Allowed by policy"
    }
  };

  const normalized = normalizeOpaDecision(payload);

  assert.equal(normalized.allow, true);
  assert.equal(normalized.reason, "Allowed by policy");
  assert.equal(normalized.decision, "ALLOW");
});

test("normalizeOpaDecision treats throttle decisions as not allowed", () => {
  const payload = {
    result: {
      allow: true,
      decision: "THROTTLE",
      actions: ["ENFORCE_COOLDOWN"],
      cooldown_seconds: 60,
      reason: "Urgency manipulation detected"
    }
  };

  const normalized = normalizeOpaDecision(payload);

  assert.equal(normalized.allow, false);
  assert.equal(normalized.decision, "THROTTLE");
  assert.equal(normalized.cooldownSeconds, 60);
  assert.deepEqual(normalized.actions, ["ENFORCE_COOLDOWN"]);
});
