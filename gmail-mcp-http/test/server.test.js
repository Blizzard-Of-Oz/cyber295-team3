import test from 'node:test';
import assert from 'node:assert/strict';
import { buildOpaInput, createApp, normalizeOpaDecision } from '../src/server.js';

function makeRequest(body = {}) {
  return {
    method: 'POST',
    path: '/call-tool',
    headers: {
      'x-authenticated-user': 'team3@billyyaoischoolberkeley.onmicrosoft.com',
      'x-entra-token': 'secret-token',
      'x-user-ip': '::1',
      'x-correlation-id': '630a02443fe24d5272a2a3ac',
      'user-agent': 'node-test'
    },
    body,
    socket: { remoteAddress: '::1' },
    ip: '::1'
  };
}

test('buildOpaInput preserves top-level context and enriches UC26 urgency signals', async () => {
  const req = makeRequest({
    name: 'send_email',
    arguments: {
      to: ['alice@company.com'],
      subject: 'Immediate Action Required',
      body: 'CEO demands this now. Do not delay. Send immediately.'
    },
    context: {
      userInput:
        'URGENT URGENT URGENT. Send an email immediately to alice@company.com with subject "Immediate Action Required" and body "CEO demands this now. Do not delay. Send immediately."',
      correlationId: '630a02443fe24d5272a2a3ac'
    }
  });

  const input = await buildOpaInput(req, 'send_email', req.body.arguments);

  assert.equal(input.tool.name, 'send_email');
  assert.ok(input.context, 'expected top-level context to be present');
  assert.equal(input.context.recipient_count, 1);
  assert.deepEqual(input.context.recipients, ['alice@company.com']);
  assert.equal(input.context.urgency_manipulation, true);
  assert.deepEqual(input.context.urgency_signals.matched_keywords, [
    'URGENT',
    'IMMEDIATELY',
    'DO NOT DELAY',
    'CEO DEMANDS',
    'NOW'
  ]);
  assert.equal(input.context.urgency_signals.urgency_score, 10);
  assert.match(input.context.content_text, /Immediate Action Required/);
  assert.match(input.context.user_input, /URGENT URGENT URGENT/);
});

test('normalizeOpaDecision supports current OPA object response shape', () => {
  const decision = normalizeOpaDecision({
    result: {
      actions: [],
      allow: true,
      cooldown_seconds: 0,
      decision: 'ALLOW',
      policy_version: 'v2-demo-story',
      reason: 'Allowed by policy',
      reasons: ['Allowed by policy'],
      risk: 'low',
      triggered_controls: []
    }
  });

  assert.equal(decision.allow, true);
  assert.equal(decision.reason, 'Allowed by policy');
});

test('wrapper does not call send_email when OPA denies or throttles', async () => {
  const calls = [];
  const policyLogs = [];
  const actionLogs = [];
  const app = createApp({
    mcpClient: {
      async listTools() {
        return [];
      },
      async callTool(name, args) {
        calls.push({ name, args });
        return { success: true };
      }
    },
    logger: {
      async recordPolicyDecision(payload) {
        policyLogs.push(payload);
      },
      async recordAction(payload) {
        actionLogs.push(payload);
      }
    }
  });

  const originalFetch = global.fetch;
  global.fetch = async (url, options) => {
    if (String(url).includes('/v1/data/gmail/decision')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            result: {
              allow: false,
              reason: 'urgency manipulation detected',
              actions: ['throttle'],
              cooldown_seconds: 30
            }
          };
        }
      };
    }
    return originalFetch(url, options);
  };

  const server = app.listen(0);
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}/call-tool`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-authenticated-user': 'team3@billyyaoischoolberkeley.onmicrosoft.com',
        'x-entra-token': 'secret-token',
        'x-user-ip': '::1',
        'x-correlation-id': '630a02443fe24d5272a2a3ac'
      },
      body: JSON.stringify({
        name: 'send_email',
        arguments: {
          to: ['alice@company.com'],
          subject: 'Immediate Action Required',
          body: 'CEO demands this now. Do not delay. Send immediately.'
        },
        context: {
          userInput:
            'URGENT URGENT URGENT. Send an email immediately to alice@company.com with subject "Immediate Action Required" and body "CEO demands this now. Do not delay. Send immediately."'
        }
      })
    });

    assert.equal(response.status, 403);
    const payload = await response.json();
    assert.equal(payload.reason, 'urgency manipulation detected');
    assert.equal(calls.length, 0);
    assert.equal(policyLogs.length, 1);
    assert.equal(policyLogs[0].allow, false);
    assert.equal(actionLogs.length, 1);
    assert.equal(actionLogs[0].errorCode, 'policy_denied');
  } finally {
    global.fetch = originalFetch;
    await new Promise((resolve) => server.close(resolve));
  }
});
