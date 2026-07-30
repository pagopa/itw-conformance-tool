import { generateKeyPairSync } from 'node:crypto';

import { extractClientIdPrefix } from '@pagopa/io-wallet-oid4vp';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { describeFederationKeyRequestObject, reissueRequestObjectJwt } from '../request-object.js';

import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { JWK } from 'jose';

const RP_BASE_URL = 'https://rp.example.org';
const SIGNING_KID = 'rp-signing-key';
// Stands in for the RP's self-signed certificate: the `federation-key` mutation
// only has to drop it, never parse it.
const CERTIFICATE = 'MIIBdummycertificate';

function generateSigningJwk(): JWK & { kid: string } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' }) as JWK;
  return { ...jwk, alg: 'ES256', kid: SIGNING_KID, use: 'sig' };
}

/** Builds a nominal Request Object as the SDK produces it at IT Wallet 1.3:
 * an `x5c` certificate chain in the header and the `x509_hash` Client Identifier
 * Prefix in the claims. */
async function createNominalRequestObject(signingJwk: JWK): Promise<string> {
  const key = await importJWK(signingJwk, 'ES256');

  return new SignJWT({
    client_id: `x509_hash:${RP_BASE_URL}`,
    iss: RP_BASE_URL,
    nonce: 'a-nonce',
    response_mode: 'direct_post.jwt',
    response_type: 'vp_token',
    response_uri: `${RP_BASE_URL}/auth/response`,
    state: 'a-state'
  })
    .setProtectedHeader({ alg: 'ES256', kid: SIGNING_KID, typ: 'oauth-authz-req+jwt', x5c: [CERTIFICATE] })
    .sign(key);
}

describe('reissueRequestObjectJwt — federation-key mutation (WP_084)', () => {
  it('removes every key source except the federation-published kid', async () => {
    const signingJwk = generateSigningJwk();
    const nominal = await createNominalRequestObject(signingJwk);

    expect(decodeProtectedHeader(nominal).x5c, 'the nominal Request Object must carry a certificate chain').toEqual([
      CERTIFICATE
    ]);

    const jwt = await reissueRequestObjectJwt({
      jwt: nominal,
      mutation: { type: 'federation-key' },
      signingPrivateJwk: signingJwk as Jwk
    });

    const header = decodeProtectedHeader(jwt);
    expect(header.x5c, 'the certificate chain is the alternative key source WP_084 removes').toBeUndefined();
    expect(
      header.trust_chain,
      'an inlined Trust Chain would carry the Entity Configuration into the header'
    ).toBeUndefined();
    expect(header.kid, 'the kid is the only remaining handle on the signing key').toBe(SIGNING_KID);
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('oauth-authz-req+jwt');
  });

  it('switches the Client Identifier Prefix to openid_federation without changing the identifier', async () => {
    const signingJwk = generateSigningJwk();
    const jwt = await reissueRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      mutation: { type: 'federation-key' },
      signingPrivateJwk: signingJwk as Jwk
    });

    const claims = decodeJwt(jwt);
    expect(claims.client_id).toBe(`openid_federation:${RP_BASE_URL}`);

    // WP_086 stays satisfied: once the prefix is stripped, the client_id is
    // still the same entity as the Request Object `iss` (and as the engagement
    // client_id and the Entity Configuration `sub`, both of which are BASE_URL).
    const { clientId, prefix } = extractClientIdPrefix(claims.client_id as string);
    expect(prefix).toBe('openid_federation');
    expect(clientId).toBe(RP_BASE_URL);
    expect(clientId).toBe(claims.iss);
  });

  it('keeps the Request Object validly signed with the nominal key', async () => {
    const signingJwk = generateSigningJwk();
    const jwt = await reissueRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      mutation: { type: 'federation-key' },
      signingPrivateJwk: signingJwk as Jwk
    });

    // The key a wallet resolves from metadata.openid_credential_verifier.jwks by
    // `kid` is the public half of the key that signed this: nothing about the
    // Request Object is defective, only its key discovery path changed.
    const { d, ...publicJwk } = signingJwk;
    void d;
    const { payload } = await jwtVerify(jwt, await importJWK(publicJwk, 'ES256'));

    expect(payload.iss).toBe(RP_BASE_URL);
    expect(payload.nonce).toBe('a-nonce');
    expect(payload.response_type).toBe('vp_token');
  });

  it('echoes a wallet_nonce alongside the mutation on a POST retrieval', async () => {
    const signingJwk = generateSigningJwk();
    const jwt = await reissueRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      mutation: { type: 'federation-key' },
      signingPrivateJwk: signingJwk as Jwk,
      walletNonce: 'wallet-provided-nonce'
    });

    expect(decodeJwt(jwt).wallet_nonce).toBe('wallet-provided-nonce');
    expect(decodeProtectedHeader(jwt).x5c).toBeUndefined();
  });

  it('reports what was actually served as fault evidence', async () => {
    const signingJwk = generateSigningJwk();
    const jwt = await reissueRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      mutation: { type: 'federation-key' },
      signingPrivateJwk: signingJwk as Jwk
    });

    expect(describeFederationKeyRequestObject(jwt)).toEqual({
      clientId: `openid_federation:${RP_BASE_URL}`,
      hasX5c: false,
      signingKeyId: SIGNING_KID
    });
  });

  it('leaves the nominal header untouched when no mutation is requested', async () => {
    const signingJwk = generateSigningJwk();
    const jwt = await reissueRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      signingPrivateJwk: signingJwk as Jwk,
      walletNonce: 'wallet-provided-nonce'
    });

    const header = decodeProtectedHeader(jwt);
    expect(header.x5c, 'only the federation-key profile may drop the certificate chain').toEqual([CERTIFICATE]);
    expect(decodeJwt(jwt).client_id).toBe(`x509_hash:${RP_BASE_URL}`);
  });
});
