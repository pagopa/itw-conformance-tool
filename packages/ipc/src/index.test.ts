import { describe, expect, test } from 'vitest';

import { parseIpcMessage, SERVICE_PROTOCOL_VERSION } from './index.js';

describe('service IPC protocol', () => {
  test('accepts a correlated stop request', () => {
    expect(
      parseIpcMessage({ version: SERVICE_PROTOCOL_VERSION, type: 'service.stop', requestId: 'request-1' })
    ).toEqual({
      version: SERVICE_PROTOCOL_VERSION,
      type: 'service.stop',
      requestId: 'request-1'
    });
  });

  test('rejects malformed and unsupported messages without throwing', () => {
    expect(parseIpcMessage(null)).toBeUndefined();
    expect(parseIpcMessage({ version: 99, type: 'service.stop', requestId: 'request-1' })).toBeUndefined();
    expect(parseIpcMessage({ version: SERVICE_PROTOCOL_VERSION, type: 'service.stop' })).toBeUndefined();
    expect(parseIpcMessage({ version: SERVICE_PROTOCOL_VERSION, type: 'service.unknown' })).toBeUndefined();
  });
});
