import { describe, expect, it } from 'vitest';

import { buildEntityConfigurationMetadata } from '../../federation/entity-configuration.js';

describe('WP_116 - Federation metadata endpoint validation', () => {
  it('builds verifier metadata containing a valid erasure endpoint', () => {
    const metadata = buildEntityConfigurationMetadata({
      entityId: 'http://localhost:8080',
      erasureUri: 'http://localhost:8080/auth/erasure',
      requestUri: 'http://localhost:8080/auth/request',
      responseUri: 'http://localhost:8080/auth/response',
      verifierJwks: {
        keys: [
          {
            kid: 'kid-1',
            kty: 'EC'
          }
        ]
      }
    });

    expect(metadata.openid_credential_verifier?.erasure_endpoint).toBe('http://localhost:8080/auth/erasure');
    expect(metadata.openid_credential_verifier?.request_uris).toEqual(['http://localhost:8080/auth/request']);
    expect(metadata.openid_credential_verifier?.response_uris).toEqual(['http://localhost:8080/auth/response']);
  });
});
