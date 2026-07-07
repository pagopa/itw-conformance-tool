import { describe, expect, it } from 'vitest';

import { buildEntityConfigurationMetadata } from '../../federation/entity-configuration.js';

describe('RP local - Federation metadata exposes erasure endpoint', () => {
  it('builds verifier metadata containing a valid erasure endpoint', () => {
    const metadata = buildEntityConfigurationMetadata({
      entityId: 'https://localhost:8080',
      erasureUri: 'https://localhost:8080/auth/erasure',
      requestUri: 'https://localhost:8080/auth/request',
      responseUri: 'https://localhost:8080/auth/response',
      verifierJwks: {
        keys: [
          {
            kid: 'kid-1',
            kty: 'EC'
          }
        ]
      }
    });

    if (!metadata) {
      throw new Error('Expected metadata to be defined');
    }

    expect(metadata.openid_credential_verifier?.erasure_endpoint).toBe('https://localhost:8080/auth/erasure');
    expect(metadata.openid_credential_verifier?.request_uris).toEqual(['https://localhost:8080/auth/request']);
    expect(metadata.openid_credential_verifier?.response_uris).toEqual(['https://localhost:8080/auth/response']);
  });
});
