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

  test('accepts a correlated issuer fault activation request', () => {
    expect(
      parseIpcMessage({
        version: SERVICE_PROTOCOL_VERSION,
        type: 'issuer.fault.activate',
        requestId: 'request-2',
        scenarioId: 'scenario-1',
        specVersion: '1.4',
        profile: { type: 'invalid-trust-anchor' }
      })
    ).toEqual({
      version: SERVICE_PROTOCOL_VERSION,
      type: 'issuer.fault.activate',
      requestId: 'request-2',
      scenarioId: 'scenario-1',
      specVersion: '1.4',
      profile: { type: 'invalid-trust-anchor' }
    });
  });

  test('accepts a correlated issuer fault deactivation round-trip', () => {
    expect(
      parseIpcMessage({
        version: SERVICE_PROTOCOL_VERSION,
        type: 'issuer.fault.deactivate',
        requestId: 'request-3',
        scenarioId: 'scenario-1'
      })
    ).toEqual({
      version: SERVICE_PROTOCOL_VERSION,
      type: 'issuer.fault.deactivate',
      requestId: 'request-3',
      scenarioId: 'scenario-1'
    });

    expect(
      parseIpcMessage({
        version: SERVICE_PROTOCOL_VERSION,
        type: 'issuer.fault.deactivated',
        requestId: 'request-3',
        scenarioId: 'scenario-1'
      })
    ).toEqual({
      version: SERVICE_PROTOCOL_VERSION,
      type: 'issuer.fault.deactivated',
      requestId: 'request-3',
      scenarioId: 'scenario-1'
    });
  });

  test('rejects an issuer fault activation request with an unknown profile', () => {
    expect(
      parseIpcMessage({
        version: SERVICE_PROTOCOL_VERSION,
        type: 'issuer.fault.activate',
        requestId: 'request-4',
        scenarioId: 'scenario-1',
        specVersion: '1.4',
        profile: { type: 'not-a-real-profile' }
      })
    ).toBeUndefined();
  });
});
