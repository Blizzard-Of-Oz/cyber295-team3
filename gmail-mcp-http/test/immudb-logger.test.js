import test from 'node:test';
import assert from 'node:assert/strict';
import { ImmuDBLogger } from '../src/immudb-logger.js';

function makeMockLogger(sqlQueryImpl) {
  const logger = Object.create(ImmuDBLogger.prototype);
  logger.enabled = true;
  logger.useSql = true;
  logger.debugEnabled = false;
  logger.debugLog = () => {};
  logger.init = async () => {};
  logger.reAuthenticate = async () => {};
  logger.client = {
    SQLQuery: sqlQueryImpl
  };
  return logger;
}

test('fetchRecentSuccessfulSendActions supports SQLQuery array return shape', async () => {
  const logger = makeMockLogger(async () => [
    {
      authenticated_user: { prop: 'user@example.com' },
      target_user_id: { prop: 'jimmy.m.yammine+uc29b@gmail.com' },
      recipient: { prop: '' },
      subject: { prop: 'Part 1' },
      message_bytes: { prop: '20' },
      attachment_bytes: { prop: '0' },
      action: { prop: 'send_email' },
      status: { prop: 'success' },
      ts: { prop: new Date().toISOString() }
    }
  ]);

  const rows = await logger.fetchRecentSuccessfulSendActions({
    authenticatedUser: 'user@example.com',
    normalizedRecipient: 'jimmy.m.yammine+uc29b@gmail.com'
  });

  assert.equal(rows.length, 1);
});

test('fetchRecentAllowedPolicyDecisions supports SQLQuery object-with-rows return shape', async () => {
  const logger = makeMockLogger(async () => ({
    rows: [
      {
        authenticated_user: { prop: 'user@example.com' },
        tool_name: { prop: 'send_email' },
        target_user_id: { prop: 'jimmy.m.yammine+uc29b@gmail.com' },
        recipient: { prop: '' },
        subject: { prop: 'Part 1' },
        message_bytes: { prop: '20' },
        attachment_bytes: { prop: '0' },
        allow: { prop: 'true' },
        ts: { prop: new Date().toISOString() },
        opa_request: { prop: '{}' }
      }
    ]
  }));

  const rows = await logger.fetchRecentAllowedPolicyDecisions({
    authenticatedUser: 'user@example.com',
    toolName: 'send_email',
    normalizedRecipient: 'jimmy.m.yammine+uc29b@gmail.com'
  });

  assert.equal(rows.length, 1);
});

test('fetchRecentAllowedPolicyDecisions keeps filtering behavior after token re-auth retry', async () => {
  let calls = 0;
  const logger = makeMockLogger(async () => {
    calls += 1;
    if (calls === 1) {
      const error = new Error('token has expired');
      error.code = 7;
      error.details = 'token has expired';
      throw error;
    }
    return {
      rows: [
        {
          authenticated_user: { prop: 'user@example.com' },
          tool_name: { prop: 'send_email' },
          target_user_id: { prop: 'other@gmail.com' },
          recipient: { prop: '' },
          subject: { prop: 'Part X' },
          message_bytes: { prop: '20' },
          attachment_bytes: { prop: '0' },
          allow: { prop: 'true' },
          ts: { prop: new Date().toISOString() },
          opa_request: { prop: '{}' }
        },
        {
          authenticated_user: { prop: 'user@example.com' },
          tool_name: { prop: 'send_email' },
          target_user_id: { prop: 'jimmy.m.yammine+uc29b@gmail.com' },
          recipient: { prop: '' },
          subject: { prop: 'Part 1' },
          message_bytes: { prop: '20' },
          attachment_bytes: { prop: '0' },
          allow: { prop: 'true' },
          ts: { prop: new Date().toISOString() },
          opa_request: { prop: '{}' }
        }
      ]
    };
  });

  const rows = await logger.fetchRecentAllowedPolicyDecisions({
    authenticatedUser: 'user@example.com',
    toolName: 'send_email',
    normalizedRecipient: 'jimmy.m.yammine+uc29b@gmail.com'
  });

  assert.equal(rows.length, 1);
  assert.equal(rows[0].target_user_id, 'jimmy.m.yammine+uc29b@gmail.com');
});
