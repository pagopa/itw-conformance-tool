import { describe, expect, it } from 'vitest';

import { buildEntityConfigurationMetadata } from '../../federation/entity-configuration.js';

describe('WP_116 - Federation metadata endpoint validation', () => {
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

    expect(metadata.openid_credential_verifier?.erasure_endpoint).toBe('https://localhost:8080/auth/erasure');
    expect(metadata.openid_credential_verifier?.request_uris).toEqual(['https://localhost:8080/auth/request']);
    expect(metadata.openid_credential_verifier?.response_uris).toEqual(['https://localhost:8080/auth/response']);
  });
});
