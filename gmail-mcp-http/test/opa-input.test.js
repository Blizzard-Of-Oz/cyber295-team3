import test from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';

const {
  buildOpaInput,
  collectRecipientAddresses,
  computeRecipientCountersFromPolicyRows,
  isExternalRecipient
} = await import('../src/server.js');

test('collectRecipientAddresses normalizes and de-duplicates recipients', () => {
  const recipients = collectRecipientAddresses({
    to: ['Personal@Gmail.com', 'personal@gmail.com'],
    cc: 'ally@example.com',
    message: { bcc: ['audit@example.com'] }
  });

  assert.deepEqual(recipients, ['personal@gmail.com', 'ally@example.com', 'audit@example.com']);
});

test('isExternalRecipient prefers external recipients', () => {
  assert.equal(isExternalRecipient('partner@gmail.com', 'employee@company.com'), true);
  assert.equal(isExternalRecipient('peer@company.com', 'employee@company.com'), false);
});

test('computeRecipientCountersFromPolicyRows increments for same sender + recipient', () => {
  const nowIso = new Date().toISOString();
  const rows = [
    {
      ts: nowIso,
      opa_request: {
        tool: {
          arguments: {
            to: 'personal@gmail.com',
            subject: 'Part 1',
            body: 'A'
          }
        }
      }
    },
    {
      ts: nowIso,
      opa_request: {
        tool: {
          arguments: {
            to: ['personal@gmail.com'],
            subject: 'Part 2',
            body: 'B'
          }
        }
      }
    }
  ];

  const counters = computeRecipientCountersFromPolicyRows({
    rows,
    recipient: 'personal@gmail.com',
    currentSubject: 'Part 3',
    currentMessageBytes: 10,
    currentAttachmentBytes: 0,
    now: Date.now()
  });

  assert.equal(counters.emails_to_same_recipient_last_24h, 2);
  assert.equal(counters.emails_to_same_recipient_last_1h, 2);
  assert.equal(counters.unique_subjects_to_same_recipient_last_24h, 3);
  assert.ok(counters.aggregate_data_volume_to_recipient_last_24h_bytes >= 10);
});

test('buildOpaInput includes UC29 counters in top-level context', async () => {
  const req = {
    method: 'POST',
    path: '/call-tool',
    headers: {
      'x-authenticated-user': 'employee@company.com',
      'x-user-ip': '10.0.0.8'
    },
    body: { some: 'payload' },
    socket: { remoteAddress: '127.0.0.1' }
  };

  const input = await buildOpaInput(req, 'send_email', {
    to: 'personal@gmail.com',
    subject: 'Part 1',
    body: 'hello'
  });

  assert.equal(typeof input.context.counters.emails_to_same_recipient_last_24h, 'number');
  assert.equal(
    typeof input.context.counters.aggregate_data_volume_to_recipient_last_24h_bytes,
    'number'
  );
  assert.equal(input.context.counters.recipient, 'personal@gmail.com');
});
