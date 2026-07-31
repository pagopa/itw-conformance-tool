import { generateKeyPairSync } from 'node:crypto';

import { decodeJwt, decodeProtectedHeader, importJWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { describeRequestObjectKeyResolution, reissueRequestObjectJwt, toX509HashClientId } from '../request-object.js';

import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { JWK } from 'jose';

const RP_BASE_URL = 'https://rp.example.org';
const SIGNING_KID = 'rp-signing-key';
// Stands in for the RP's self-signed certificate: these rewrites carry it
// through the header, never parse it.
const CERTIFICATE = 'MIIBdummycertificate';
// The x509_hash client_id is the hash of that certificate, so it carries no
// entity identifier at all — unlike the openid_federation one below.
const NOMINAL_CLIENT_ID = toX509HashClientId(CERTIFICATE);

function generateSigningJwk(): JWK & { kid: string } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' }) as JWK;
  return { ...jwk, alg: 'ES256', kid: SIGNING_KID, use: 'sig' };
}

/** Builds a nominal Request Object as the SDK produces it at IT Wallet 1.4:
 * an `x5c` certificate chain in the header and the `x509_hash` Client Identifier
 * Prefix in the claims. */
async function createNominalRequestObject(signingJwk: JWK): Promise<string> {
  const key = await importJWK(signingJwk, 'ES256');

  return new SignJWT({
    client_id: NOMINAL_CLIENT_ID,
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

/** The same Request Object as the RP stores it for an `openid_federation`
 * engagement: no `x5c`, no inlined Trust Chain, and the entity identifier behind
 * the prefix, so `kid` is the only handle a wallet has on the signing key. */
async function createFederationRequestObject(signingJwk: JWK): Promise<string> {
  return new SignJWT({
    client_id: `openid_federation:${RP_BASE_URL}`,
    iss: RP_BASE_URL,
    nonce: 'a-nonce',
    response_mode: 'direct_post.jwt',
    response_type: 'vp_token',
    response_uri: `${RP_BASE_URL}/auth/response`,
    state: 'a-state'
  })
    .setProtectedHeader({ alg: 'ES256', kid: SIGNING_KID, typ: 'oauth-authz-req+jwt' })
    .sign(await importJWK(signingJwk, 'ES256'));
}

describe('describeRequestObjectKeyResolution', () => {
  it('reports the federation shape actually served', async () => {
    const jwt = await createFederationRequestObject(generateSigningJwk());

    expect(describeRequestObjectKeyResolution(jwt)).toEqual({
      clientIdPrefix: 'openid_federation',
      hasX5c: false,
      signingKeyId: SIGNING_KID
    });
  });

  it('reports the x509_hash shape actually served', async () => {
    expect(describeRequestObjectKeyResolution(await createNominalRequestObject(generateSigningJwk()))).toEqual({
      clientIdPrefix: 'x509_hash',
      hasX5c: true,
      signingKeyId: SIGNING_KID
    });
  });
});

describe('reissueRequestObjectJwt', () => {
  it('leaves the header and the client identifier untouched when no mutation is requested', async () => {
    const signingJwk = generateSigningJwk();
    const jwt = await reissueRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      signingPrivateJwk: signingJwk as Jwk,
      walletNonce: 'wallet-provided-nonce'
    });

    const header = decodeProtectedHeader(jwt);
    expect(header.x5c, 'the retrieval-time rewrite may not change the key resolution path').toEqual([CERTIFICATE]);
    expect(decodeJwt(jwt).client_id).toBe(NOMINAL_CLIENT_ID);
  });

  it('carries a stored federation Request Object through a POST retrieval untouched', async () => {
    // The stored artifact is already in its federation shape, so the
    // retrieval-time rewrite must not reintroduce a key source the engagement
    // did not announce (WP_084).
    const signingJwk = generateSigningJwk();
    const jwt = await reissueRequestObjectJwt({
      jwt: await createFederationRequestObject(signingJwk),
      signingPrivateJwk: signingJwk as Jwk,
      walletNonce: 'wallet-provided-nonce'
    });

    expect(decodeJwt(jwt).wallet_nonce).toBe('wallet-provided-nonce');
    expect(decodeJwt(jwt).client_id).toBe(`openid_federation:${RP_BASE_URL}`);
    expect(decodeProtectedHeader(jwt).x5c).toBeUndefined();
  });
});
