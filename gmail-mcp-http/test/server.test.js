import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  analyzeUrl,
  buildOpaInput,
  createApp,
  extractUrlsFromText,
  normalizeOpaDecision
} from '../src/server.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
  assert.deepEqual(input.context.urls, []);
  assert.equal(input.context.dns_tunneling_detected, false);
});

test('extractUrlsFromText finds URLs across send_email content without duplicates', () => {
  const urls = extractUrlsFromText(
    'Subject mentions https://example.com/download?data=abc',
    'Body repeats https://example.com/download?data=abc and adds https://a8f3b2c.exfil-c2-domain.com'
  );

  assert.deepEqual(urls, [
    'https://example.com/download?data=abc',
    'https://a8f3b2c.exfil-c2-domain.com'
  ]);
});

test('buildOpaInput enriches top-level context with URL analysis for UC28', async () => {
  const req = makeRequest({
    name: 'send_email',
    arguments: {
      to: ['alice@company.com'],
      subject: 'Helpful resources',
      body: 'Please review this link: https://example.com/download?data=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=='
    },
    context: {}
  });

  const input = await buildOpaInput(req, 'send_email', req.body.arguments);

  assert.equal(input.context.urls.length, 1);
  assert.equal(
    input.context.urls[0].original_url,
    'https://example.com/download?data=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=='
  );
  assert.equal(input.context.urls[0].hostname, 'example.com');
  assert.equal(input.context.urls[0].query_param_count, 1);
  assert.equal(input.context.urls[0].query_values_look_base64, true);
  assert.equal(input.context.urls[0].suspicious_query_payload, true);
  assert.equal(input.context.urls[0].long_query_string, true);
  assert.equal(input.context.dns_tunneling_detected, true);
  assert.equal(input.context.dns_tunneling_signals.flagged_reasons.suspicious_query_payload_count, 1);
});

test('analyzeUrl flags high-entropy and base64-like subdomains deterministically', () => {
  const base64ish = analyzeUrl('https://YWRtaW46cGFzc3dvcmQ.exfil-domain.com');
  const entropyish = analyzeUrl('https://q9x4b7n2m5k8z1.exfil-c2-domain.com/path');

  assert.equal(base64ish.looks_base64_subdomain, true);
  assert.equal(base64ish.high_entropy_subdomain, true);
  assert.equal(entropyish.high_entropy_subdomain, true);
});

test('analyzeUrl flags suspicious C2 and exfiltration domain keywords', () => {
  const analyzed = analyzeUrl('https://a8f3b2c.exfil-c2-domain.com');

  assert.deepEqual(analyzed.suspicious_domain_keywords, ['exfil', 'c2']);
  assert.equal(analyzed.suspicious_domain_pattern, true);
  assert.equal(analyzed.suspicious_hostname_pattern, true);
});

test('buildOpaInput sets dns_tunneling_detected for suspicious exfil domains', async () => {
  const req = makeRequest({
    name: 'send_email',
    arguments: {
      to: ['alice@company.com'],
      subject: 'Helpful resources',
      body: 'Please review this link: https://a8f3b2c.exfil-c2-domain.com'
    }
  });

  const input = await buildOpaInput(req, 'send_email', req.body.arguments);

  assert.equal(input.context.urls.length, 1);
  assert.equal(input.context.urls[0].suspicious_domain_pattern, true);
  assert.equal(input.context.urls[0].suspicious_hostname_pattern, true);
  assert.deepEqual(input.context.urls[0].suspicious_domain_keywords, ['exfil', 'c2']);
  assert.equal(input.context.dns_tunneling_detected, true);
  assert.equal(input.context.dns_tunneling_signals.flagged_url_count, 1);
  assert.equal(input.context.dns_tunneling_signals.flagged_reasons.suspicious_domain_pattern_count, 1);
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

test('wrapper returns policy denial for UC28 suspicious encoded URL case', async () => {
  const calls = [];
  const policyLogs = [];
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
      async recordAction() {}
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
              reason: 'base64-like payload in query string detected'
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
        'x-correlation-id': 'cb83b932d735a9fbbe3cafd0'
      },
      body: JSON.stringify({
        name: 'send_email',
        arguments: {
          to: ['alice@company.com'],
          subject: 'Helpful resources',
          body: 'Please review this link: https://example.com/download?data=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=='
        }
      })
    });

    assert.equal(response.status, 403);
    const payload = await response.json();
    assert.equal(payload.reason, 'base64-like payload in query string detected');
    assert.equal(calls.length, 0);
    assert.equal(policyLogs.length, 1);
    assert.equal(policyLogs[0].allow, false);
    assert.equal(policyLogs[0].opaRequest.context.dns_tunneling_detected, true);
    assert.equal(policyLogs[0].opaRequest.context.urls[0].suspicious_query_payload, true);
  } finally {
    global.fetch = originalFetch;
    await new Promise((resolve) => server.close(resolve));
  }
});

test('wrapper returns policy denial for UC28 suspicious C2 domain case', async () => {
  const calls = [];
  const policyLogs = [];
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
      async recordAction() {}
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
              reason: 'dns tunneling / suspicious c2 domain detected'
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
        'x-correlation-id': 'e7181d0bf25e226825773ed0'
      },
      body: JSON.stringify({
        name: 'send_email',
        arguments: {
          to: ['alice@company.com'],
          subject: 'Helpful resources',
          body: 'Please review this link: https://a8f3b2c.exfil-c2-domain.com'
        }
      })
    });

    assert.equal(response.status, 403);
    const payload = await response.json();
    assert.equal(payload.reason, 'dns tunneling / suspicious c2 domain detected');
    assert.equal(calls.length, 0);
    assert.equal(policyLogs.length, 1);
    assert.equal(policyLogs[0].allow, false);
    assert.equal(policyLogs[0].opaRequest.context.dns_tunneling_detected, true);
    assert.equal(policyLogs[0].opaRequest.context.urls[0].suspicious_domain_pattern, true);
    assert.equal(policyLogs[0].opaRequest.context.urls[0].suspicious_hostname_pattern, true);
  } finally {
    global.fetch = originalFetch;
    await new Promise((resolve) => server.close(resolve));
  }
});

test('gmail rego policy includes UC28 DNS tunneling deny rules and preserves UC26 rule', () => {
  const newPath = path.resolve(__dirname, '../../opa_policies/gmail.rego');
  const legacyPath = path.resolve(__dirname, '../../opa-policies/gmail.rego');
  const regoPath = fs.existsSync(newPath) ? newPath : legacyPath;
  const rego = fs.readFileSync(regoPath, 'utf8');

  assert.match(rego, /send_email_urgency_manipulation_block|urgency_exploitation/);
  assert.match(rego, /suspicious_query_payload/);
  assert.match(rego, /suspicious_domain_pattern/);
  assert.match(rego, /suspicious_hostname_pattern/);
  assert.match(rego, /looks_base64_subdomain/);
  assert.match(rego, /high_entropy_subdomain/);
  assert.match(rego, /long_query_string/);
});
