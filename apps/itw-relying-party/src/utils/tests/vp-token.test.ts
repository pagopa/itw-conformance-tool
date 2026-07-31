import { beforeAll, describe, expect, it } from 'vitest';

import { toX509HashClientId } from '../request-object.js';
import { VpTokenVerifier } from '../vp-token.js';
import {
  createCertificateBase64Der,
  createSdJwtPresentation,
  CREDENTIAL_ID,
  DCQL_QUERY,
  DISCLOSED_CLAIMS,
  generateEcJwk,
  PRESENTATION_NONCE
} from './fixtures/presentation.js';

import type { Openid4vpAuthorizationRequestPayload, ParseAuthorizationResponseResult } from '@pagopa/io-wallet-oid4vp';

const RP_BASE_URL = 'https://rp.example.org';

let nominalClientId: string;

beforeAll(async () => {
  const rpCertificate = await createCertificateBase64Der(
    generateEcJwk({ alg: 'ES256', kid: 'rp-signing-key', use: 'sig' })
  );
  nominalClientId = toX509HashClientId(rpCertificate);
});

function createVerifier(presentation: string): VpTokenVerifier {
  return new VpTokenVerifier({
    authResponse: {
      authorizationResponsePayload: { vp_token: { [CREDENTIAL_ID]: [presentation] } },
      expectedNonce: PRESENTATION_NONCE
    } as unknown as ParseAuthorizationResponseResult,
    iacaX509: '',
    relyingPartyEntityId: RP_BASE_URL,
    requestObject: {
      client_id: nominalClientId,
      dcql_query: DCQL_QUERY
    } as unknown as Openid4vpAuthorizationRequestPayload
  });
}

describe('VpTokenVerifier — key binding audience', () => {
  it('accepts the Relying Party entity identifier, which IT Wallet mandates', async () => {
    const verifier = createVerifier(await createSdJwtPresentation({ audience: RP_BASE_URL }));

    await expect(verifier.verifyCredentials()).resolves.toEqual([DISCLOSED_CLAIMS]);
    expect(verifier.keyBindingAudiences).toEqual([
      { aud: RP_BASE_URL, credentialId: CREDENTIAL_ID, form: 'entity-identifier' }
    ]);
  });

  it('accepts the full prefixed client_id, which OpenID4VP 1.0 mandates instead', async () => {
    // Failing an otherwise-correct wallet over which of the two specs it read
    // would be a false negative, so both are accepted and the form is recorded.
    const verifier = createVerifier(await createSdJwtPresentation({ audience: nominalClientId }));

    await expect(verifier.verifyCredentials()).resolves.toEqual([DISCLOSED_CLAIMS]);
    expect(verifier.keyBindingAudiences).toEqual([
      { aud: nominalClientId, credentialId: CREDENTIAL_ID, form: 'prefixed-client-id' }
    ]);
  });

  it('rejects any other audience', async () => {
    const verifier = createVerifier(await createSdJwtPresentation({ audience: 'https://attacker.example.org' }));

    await expect(verifier.verifyCredentials()).rejects.toThrow(/key binding 'aud'/);
    expect(verifier.keyBindingAudiences).toEqual([]);
  });

  it('rejects the bare certificate hash without its prefix', async () => {
    // The audience is the *full* Client Identifier; the hash alone is neither
    // accepted form.
    const bareHash = nominalClientId.slice('x509_hash:'.length);
    const verifier = createVerifier(await createSdJwtPresentation({ audience: bareHash }));

    await expect(verifier.verifyCredentials()).rejects.toThrow(/key binding 'aud'/);
  });

  it('names both accepted forms when it rejects', async () => {
    const verifier = createVerifier(await createSdJwtPresentation({ audience: 'https://attacker.example.org' }));

    await expect(verifier.verifyCredentials()).rejects.toThrow(
      new RegExp(`${RP_BASE_URL}.*${nominalClientId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`)
    );
  });

  it('reports the accepted audiences the Relying Party will honour', () => {
    expect(createVerifier('unused').acceptedKeyBindingAudiences).toEqual([RP_BASE_URL, nominalClientId]);
  });
});
