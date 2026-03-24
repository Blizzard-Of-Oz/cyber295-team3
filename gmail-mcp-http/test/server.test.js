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
const sharedFixtureDir = path.join(__dirname, '..', '..', 'scripts', 'TestFiles');

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

test('buildOpaInput extracts best-effort attachment text for OPA context', async () => {
  const fixtureDir = path.join(__dirname, 'fixtures');
  fs.mkdirSync(fixtureDir, { recursive: true });
  const attachmentPath = path.join(fixtureDir, `attachment-${Date.now()}.txt`);
  fs.writeFileSync(attachmentPath, 'Internal note: proprietary roadmap details.', 'utf8');

  try {
    const req = makeRequest({
      name: 'send_email',
      arguments: {
        to: ['alice@company.com'],
        subject: 'Attachment test',
        body: 'Please review.',
        attachments: [attachmentPath]
      },
      context: {}
    });

    const input = await buildOpaInput(req, 'send_email', req.body.arguments);

    assert.equal(input.context.attachments.length, 1);
    const extracted = JSON.parse(input.context.attachments[0].extracted_text);
    assert.equal(Array.isArray(extracted), true);
    assert.equal(extracted.length, 1);
    assert.equal(extracted[0].filename.endsWith('.txt'), true);
    assert.equal(extracted[0].extracted_text, 'Internal note: proprietary roadmap details.');
  } finally {
    try {
      fs.unlinkSync(attachmentPath);
    } catch (_error) {
      // ignore cleanup failure in tests
    }
  }
});

test('buildOpaInput preserves provided attachment extracted_text', async () => {
  const req = makeRequest({
    name: 'send_email',
    arguments: {
      to: ['alice@company.com'],
      subject: 'Attachment test',
      body: 'Please review.'
    },
    context: {
      attachments: [
        {
          name: 'memo.txt',
          file_ext: 'txt',
          extracted_text: 'Already extracted by upstream parser.'
        }
      ]
    }
  });

  const input = await buildOpaInput(req, 'send_email', req.body.arguments);

  assert.equal(input.context.attachments.length, 1);
  const extracted = JSON.parse(input.context.attachments[0].extracted_text);
  assert.equal(Array.isArray(extracted), true);
  assert.equal(extracted.length, 1);
  assert.equal(extracted[0].filename, 'memo.txt');
  assert.equal(extracted[0].extracted_text, 'Already extracted by upstream parser.');
});

test('buildOpaInput extracts text from real PPTX fixture and aligns detected_types with actual_ext', async () => {
  const pptxPath = path.join(sharedFixtureDir, 'normal_office365_files.pptx');
  if (!fs.existsSync(pptxPath)) {
    return;
  }

  const req = makeRequest({
    name: 'send_email',
    arguments: {
      to: ['alice@company.com'],
      subject: 'PPTX fixture test',
      body: 'Please review the deck.',
      attachments: [pptxPath]
    },
    context: {}
  });

  const input = await buildOpaInput(req, 'send_email', req.body.arguments);
  assert.equal(input.context.attachments.length, 1);

  const attachment = input.context.attachments[0];
  assert.equal(attachment.actual_ext, 'pptx');
  assert.deepEqual(attachment.detected_types, ['pptx']);

  const extracted = JSON.parse(attachment.extracted_text);
  assert.equal(Array.isArray(extracted), true);
  assert.equal(extracted.length, 1);
  assert.match(extracted[0].extracted_text, /Slide 1:/);
});

test('buildOpaInput archive contains_file_types reflects detected inner file types', async () => {
  const zipPath = path.join(sharedFixtureDir, 'spoofing_file_type.exe.txt.zip');
  if (!fs.existsSync(zipPath)) {
    return;
  }

  const req = makeRequest({
    name: 'send_email',
    arguments: {
      to: ['alice@company.com'],
      subject: 'Archive fixture test',
      body: 'Please review archive.',
      attachments: [zipPath]
    },
    context: {}
  });

  const input = await buildOpaInput(req, 'send_email', req.body.arguments);
  assert.equal(input.context.attachments.length, 1);

  const attachment = input.context.attachments[0];
  assert.equal(attachment.actual_ext, 'zip');
  assert.deepEqual(attachment.detected_types, ['zip']);
  assert.ok(Array.isArray(attachment.archive?.contains_file_types));
  assert.ok(attachment.archive.contains_file_types.length > 0);
  assert.equal(attachment.archive.contains_file_types.includes('exe'), true);
  assert.equal(attachment.archive.contains_file_types.includes('zip'), false);
});

test('buildOpaInput skips text extraction for unsupported executable fixture', async () => {
  const exePath = path.join(sharedFixtureDir, 'spoofing_file_type.exe.txt');
  if (!fs.existsSync(exePath)) {
    return;
  }

  const req = makeRequest({
    name: 'send_email',
    arguments: {
      to: ['alice@company.com'],
      subject: 'Executable fixture test',
      body: 'Please review executable.',
      attachments: [exePath]
    },
    context: {}
  });

  const input = await buildOpaInput(req, 'send_email', req.body.arguments);
  assert.equal(input.context.attachments.length, 1);
  const attachment = input.context.attachments[0];
  assert.equal(attachment.actual_ext, 'exe');
  assert.equal(attachment.extracted_text, undefined);
});

test('buildOpaInput marks password-protected ZIP archive metadata correctly', async () => {
  const zipPath = path.join(sharedFixtureDir, 'password_protected.zip');
  if (!fs.existsSync(zipPath)) {
    return;
  }

  const req = makeRequest({
    name: 'send_email',
    arguments: {
      to: ['alice@company.com'],
      subject: 'Password archive fixture test',
      body: 'Please review protected archive.',
      attachments: [zipPath]
    },
    context: {}
  });

  const input = await buildOpaInput(req, 'send_email', req.body.arguments);
  assert.equal(input.context.attachments.length, 1);
  const attachment = input.context.attachments[0];
  assert.equal(attachment.actual_ext, 'zip');
  assert.equal(attachment.archive?.password_protected, true);
});

test('buildOpaInput extracts image text via LLM OCR when enabled', async () => {
  const fixtureDir = path.join(__dirname, 'fixtures');
  fs.mkdirSync(fixtureDir, { recursive: true });
  const attachmentPath = path.join(fixtureDir, `attachment-${Date.now()}.png`);
  fs.writeFileSync(attachmentPath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0a]));

  const originalFetch = global.fetch;
  const originalOpenAiKey = process.env.OPENAI_API_KEY;
  const originalOcrEnabled = process.env.ATTACHMENT_IMAGE_OCR_WITH_LLM;

  process.env.OPENAI_API_KEY = 'test-key';
  process.env.ATTACHMENT_IMAGE_OCR_WITH_LLM = 'true';

  global.fetch = async (url) => {
    if (String(url).includes('/responses')) {
      return {
        ok: true,
        async json() {
          return {
            output_text: 'Screenshot text: internal budget FY2026'
          };
        }
      };
    }
    return originalFetch(url);
  };

  try {
    const req = makeRequest({
      name: 'send_email',
      arguments: {
        to: ['alice@company.com'],
        subject: 'Image OCR test',
        body: 'Please review image',
        attachments: [attachmentPath]
      },
      context: {}
    });

    const input = await buildOpaInput(req, 'send_email', req.body.arguments);
    assert.equal(input.context.attachments.length, 1);
    const extracted = JSON.parse(input.context.attachments[0].extracted_text);
    assert.equal(Array.isArray(extracted), true);
    assert.equal(extracted.length, 1);
    assert.equal(extracted[0].filename.endsWith('.png'), true);
    assert.equal(extracted[0].extracted_text, 'Screenshot text: internal budget FY2026');
  } finally {
    global.fetch = originalFetch;
    process.env.OPENAI_API_KEY = originalOpenAiKey;
    process.env.ATTACHMENT_IMAGE_OCR_WITH_LLM = originalOcrEnabled;
    try {
      fs.unlinkSync(attachmentPath);
    } catch (_error) {
      // ignore cleanup failure in tests
    }
  }
});

test('buildOpaInput extracts image text from nested Responses API output format', async () => {
  const fixtureDir = path.join(__dirname, 'fixtures');
  fs.mkdirSync(fixtureDir, { recursive: true });
  const attachmentPath = path.join(fixtureDir, `attachment-${Date.now()}-nested.png`);
  fs.writeFileSync(attachmentPath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0a]));

  const originalFetch = global.fetch;
  const originalOpenAiKey = process.env.OPENAI_API_KEY;
  const originalOcrEnabled = process.env.ATTACHMENT_IMAGE_OCR_WITH_LLM;

  process.env.OPENAI_API_KEY = 'test-key';
  process.env.ATTACHMENT_IMAGE_OCR_WITH_LLM = 'true';

  global.fetch = async (url) => {
    if (String(url).includes('/responses')) {
      return {
        ok: true,
        async json() {
          return {
            output: [
              {
                type: 'message',
                content: [
                  {
                    type: 'output_text',
                    text: 'Nested output text from image'
                  }
                ]
              }
            ]
          };
        }
      };
    }
    return originalFetch(url);
  };

  try {
    const req = makeRequest({
      name: 'send_email',
      arguments: {
        to: ['alice@company.com'],
        subject: 'Image OCR nested output test',
        body: 'Please review image',
        attachments: [attachmentPath]
      },
      context: {}
    });

    const input = await buildOpaInput(req, 'send_email', req.body.arguments);
    assert.equal(input.context.attachments.length, 1);
    const extracted = JSON.parse(input.context.attachments[0].extracted_text);
    assert.equal(Array.isArray(extracted), true);
    assert.equal(extracted.length, 1);
    assert.equal(extracted[0].filename.endsWith('.png'), true);
    assert.equal(extracted[0].extracted_text, 'Nested output text from image');
  } finally {
    global.fetch = originalFetch;
    process.env.OPENAI_API_KEY = originalOpenAiKey;
    process.env.ATTACHMENT_IMAGE_OCR_WITH_LLM = originalOcrEnabled;
    try {
      fs.unlinkSync(attachmentPath);
    } catch (_error) {
      // ignore cleanup failure in tests
    }
  }
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
