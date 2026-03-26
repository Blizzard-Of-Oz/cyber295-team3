import test from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';

const {
  buildOpaInput,
  collectRecipientAddresses,
  filterRowsByAuthenticatedUser,
  isExternalRecipient,
  splitTargetRecipients
} = await import('../src/server.js');

function makeReq(user = 'employee@company.com') {
  return {
    method: 'POST',
    path: '/call-tool',
    headers: {
      'x-authenticated-user': user,
      'x-user-ip': '10.0.0.8'
    },
    body: { some: 'payload' },
    socket: { remoteAddress: '127.0.0.1' }
  };
}

test('collectRecipientAddresses normalizes and de-duplicates recipients', () => {
  const recipients = collectRecipientAddresses({
    to: ['Personal@Gmail.com', 'personal@gmail.com'],
    cc: 'ally@example.com',
    message: { bcc: ['audit@example.com'] }
  });

  assert.deepEqual(recipients, ['personal@gmail.com', 'ally@example.com', 'audit@example.com']);
});

test('isExternalRecipient compares normalized domains', () => {
  assert.equal(isExternalRecipient('partner@gmail.com', 'employee@company.com'), true);
  assert.equal(isExternalRecipient('Peer@Company.com', 'employee@company.com'), false);
});

test('splitTargetRecipients normalizes comma-separated target_user_id values', () => {
  assert.deepEqual(splitTargetRecipients('A@X.com, b@y.com '), ['a@x.com', 'b@y.com']);
});

test('first send to recipient has prior count 0', async () => {
  const input = await buildOpaInput(
    makeReq(),
    'send_email',
    { to: 'jimmy.m.yammine@gmail.com', subject: 'Part 1', body: 'a' },
    { historyRowsOverride: [] }
  );

  assert.equal(input.context.counters.emails_to_same_recipient_last_24h, 0);
  assert.equal(input.context.counters.emails_to_same_recipient_last_1h, 0);
});

test('second send to same recipient has prior count 1', async () => {
  const now = new Date().toISOString();
  const input = await buildOpaInput(
    makeReq(),
    'send_email',
    { to: 'jimmy.m.yammine@gmail.com', subject: 'Part 2', body: 'b' },
    {
      historyRowsOverride: [
        {
          target_user_id: 'jimmy.m.yammine@gmail.com',
          subject: 'Part 1',
          message_bytes: 10,
          attachment_bytes: 0,
          ts: now
        }
      ]
    }
  );

  assert.equal(input.context.counters.emails_to_same_recipient_last_24h, 1);
  assert.equal(input.context.counters.emails_to_same_recipient_last_1h, 1);
});

test('third send within same hour has prior count 2', async () => {
  const now = new Date().toISOString();
  const input = await buildOpaInput(
    makeReq(),
    'send_email',
    { to: 'jimmy.m.yammine@gmail.com', subject: 'Part 3', body: 'c' },
    {
      historyRowsOverride: [
        {
          target_user_id: 'jimmy.m.yammine@gmail.com',
          subject: 'Part 1',
          message_bytes: 10,
          attachment_bytes: 0,
          ts: now
        },
        {
          target_user_id: 'jimmy.m.yammine@gmail.com',
          subject: 'Part 2',
          message_bytes: 10,
          attachment_bytes: 0,
          ts: now
        }
      ]
    }
  );

  assert.equal(input.context.counters.emails_to_same_recipient_last_24h, 2);
  assert.equal(input.context.counters.emails_to_same_recipient_last_1h, 2);
});

test('different recipient rows do not affect counters', async () => {
  const now = new Date().toISOString();
  const input = await buildOpaInput(
    makeReq(),
    'send_email',
    { to: 'jimmy.m.yammine@gmail.com', subject: 'Part X', body: 'x' },
    {
      historyRowsOverride: [
        {
          target_user_id: 'someoneelse@gmail.com',
          subject: 'Other',
          message_bytes: 42,
          attachment_bytes: 0,
          ts: now
        }
      ]
    }
  );

  assert.equal(input.context.counters.emails_to_same_recipient_last_24h, 0);
  assert.equal(input.context.counters.emails_to_same_recipient_last_1h, 0);
});

test('different user rows do not affect counters', async () => {
  const now = new Date().toISOString();
  const input = await buildOpaInput(
    makeReq('team3@billyyaoischoolberkeley.onmicrosoft.com'),
    'send_email',
    { to: 'jimmy.m.yammine@gmail.com', subject: 'Part Y', body: 'y' },
    {
      historyRowsOverride: [
        {
          authenticated_user: 'other.user@billyyaoischoolberkeley.onmicrosoft.com',
          target_user_id: 'jimmy.m.yammine@gmail.com',
          subject: 'Other User Prior',
          message_bytes: 42,
          attachment_bytes: 0,
          ts: now
        }
      ]
    }
  );

  assert.equal(input.context.counters.emails_to_same_recipient_last_24h, 0);
});

test('filterRowsByAuthenticatedUser keeps same-user rows only', () => {
  const rows = [
    { authenticated_user: 'A@x.com', target_user_id: 'u1@example.com' },
    { authenticated_user: 'b@x.com', target_user_id: 'u2@example.com' },
    { target_user_id: 'u3@example.com' }
  ];
  const scoped = filterRowsByAuthenticatedUser(rows, 'a@x.com');
  assert.equal(scoped.length, 2);
});
