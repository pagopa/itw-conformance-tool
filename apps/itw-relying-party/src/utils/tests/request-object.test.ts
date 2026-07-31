import { generateKeyPairSync } from 'node:crypto';

import { extractClientIdPrefix } from '@pagopa/io-wallet-oid4vp';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  describeRequestObjectKeyResolution,
  reissueRequestObjectJwt,
  toFederationRequestObjectJwt,
  toX509HashClientId
} from '../request-object.js';

import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { JWK } from 'jose';

const RP_BASE_URL = 'https://rp.example.org';
const SIGNING_KID = 'rp-signing-key';
// Stands in for the RP's self-signed certificate: the federation rewrite only
// has to drop it, never parse it.
const CERTIFICATE = 'MIIBdummycertificate';
// The x509_hash client_id is the hash of that certificate, so it carries no
// entity identifier at all — which is exactly why the federation rewrite has to
// be told the entity id rather than recovering it from here.
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

describe('toFederationRequestObjectJwt (WP_084)', () => {
  it('removes every key source except the federation-published kid', async () => {
    const signingJwk = generateSigningJwk();
    const nominal = await createNominalRequestObject(signingJwk);

    expect(decodeProtectedHeader(nominal).x5c, 'the nominal Request Object must carry a certificate chain').toEqual([
      CERTIFICATE
    ]);

    const jwt = await toFederationRequestObjectJwt({
      jwt: nominal,
      relyingPartyEntityId: RP_BASE_URL,
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

  it('switches the Client Identifier Prefix to openid_federation and names the entity', async () => {
    const signingJwk = generateSigningJwk();
    const jwt = await toFederationRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      relyingPartyEntityId: RP_BASE_URL,
      signingPrivateJwk: signingJwk as Jwk
    });

    const claims = decodeJwt(jwt);
    expect(claims.client_id).toBe(`openid_federation:${RP_BASE_URL}`);
    expect(claims.client_id, 'the mutation must not carry over the nominal certificate hash').not.toBe(
      NOMINAL_CLIENT_ID
    );

    // Unlike x509_hash, this prefix carries the entity identifier itself — that
    // is what points the wallet at the Trust Chain. Stripping it must yield the
    // Request Object `iss`, which is also the Entity Configuration `sub`.
    const { clientId, prefix } = extractClientIdPrefix(claims.client_id as string);
    expect(prefix).toBe('openid_federation');
    expect(clientId).toBe(RP_BASE_URL);
    expect(clientId).toBe(claims.iss);
  });

  it('keeps the Request Object validly signed with the nominal key', async () => {
    const signingJwk = generateSigningJwk();
    const jwt = await toFederationRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      relyingPartyEntityId: RP_BASE_URL,
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

  it('survives a POST retrieval that echoes a wallet_nonce', async () => {
    // The stored Request Object is already in its federation shape, so the
    // retrieval-time rewrite must carry that header through untouched.
    const signingJwk = generateSigningJwk();
    const federation = await toFederationRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      relyingPartyEntityId: RP_BASE_URL,
      signingPrivateJwk: signingJwk as Jwk
    });

    const jwt = await reissueRequestObjectJwt({
      jwt: federation,
      signingPrivateJwk: signingJwk as Jwk,
      walletNonce: 'wallet-provided-nonce'
    });

    expect(decodeJwt(jwt).wallet_nonce).toBe('wallet-provided-nonce');
    expect(decodeJwt(jwt).client_id).toBe(`openid_federation:${RP_BASE_URL}`);
    expect(decodeProtectedHeader(jwt).x5c).toBeUndefined();
  });
});

describe('describeRequestObjectKeyResolution', () => {
  it('reports the federation shape actually served', async () => {
    const signingJwk = generateSigningJwk();
    const jwt = await toFederationRequestObjectJwt({
      jwt: await createNominalRequestObject(signingJwk),
      relyingPartyEntityId: RP_BASE_URL,
      signingPrivateJwk: signingJwk as Jwk
    });

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
});
