import { generateKeyPairSync } from 'node:crypto';

import { createX509HashClientId } from '@pagopa/io-wallet-oid4vp';
import Fastify from 'fastify';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { createRpFaultStore } from '../../faults/rp-fault-store.js';
import getAuthorizationRequestRoute from '../../routes/get-authorization-request.js';
import { callbacks } from '../../utils/crypto.js';

import type { ObservedEvent } from '@itw-conformance-tool/conformance';
import type { JWK } from 'jose';

const RP_BASE_URL = 'https://rp.example.org';
const SIGNING_KID = 'rp-signing-key';
const CERTIFICATE = 'MIIBdummycertificate';
const STATE = '11111111-2222-4333-8444-555555555555';
/** Hash of the certificate above — the nominal identifier carries no entity URL. */
const NOMINAL_CLIENT_ID = await createX509HashClientId({ certificateChain: [CERTIFICATE], hash: callbacks.hash });

function generateSigningJwk(): JWK & { kid: string } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' }) as JWK;
  return { ...jwk, alg: 'ES256', kid: SIGNING_KID, use: 'sig' };
}

/** The Request Object the SDK stores at IT Wallet 1.4: `x5c` in the header and
 * the `x509_hash` Client Identifier Prefix in the claims. */
async function createStoredRequestObject(signingJwk: JWK): Promise<string> {
  return new SignJWT({
    client_id: NOMINAL_CLIENT_ID,
    iss: RP_BASE_URL,
    nonce: 'a-nonce',
    response_mode: 'direct_post.jwt',
    response_type: 'vp_token',
    response_uri: `${RP_BASE_URL}/auth/response`,
    state: STATE
  })
    .setProtectedHeader({ alg: 'ES256', kid: SIGNING_KID, typ: 'oauth-authz-req+jwt', x5c: [CERTIFICATE] })
    .sign(await importJWK(signingJwk, 'ES256'));
}

/** Boots the real route with the real fault store, decorated with only what the
 * handler reads. Mirrors the Trust Anchor's route tests.
 *
 * The trust model is decided when the Request Object is created, so it reaches
 * this handler as the shape of the stored artifact — never as a fault. */
async function buildApp(options: { signingJwk: JWK & { kid: string }; storedJwt?: string }) {
  const app = Fastify();
  const events: ObservedEvent[] = [];
  const rpFaultStore = createRpFaultStore();

  const storedJwt = options.storedJwt ?? (await createStoredRequestObject(options.signingJwk));
  const statuses: string[] = [];

  app.decorate('repository', {
    requestObject: {
      get: () => ({ id: STATE, jwt: storedJwt }),
      update: (_state: string, status: string) => statuses.push(status)
    }
  });
  app.decorate('config', { BASE_URL: RP_BASE_URL });
  app.decorate('jwks', { sig: { private: options.signingJwk } });
  app.decorate('rpFaultStore', rpFaultStore);
  app.decorate('conformanceEventSink', {
    emit: async (event: ObservedEvent) => {
      events.push(event);
    }
  });

  await app.register(getAuthorizationRequestRoute);
  await app.ready();

  return { app, events, statuses };
}

async function fetchRequestObject(app: Awaited<ReturnType<typeof buildApp>>['app']): Promise<string> {
  const response = await app.inject({ method: 'GET', url: `/auth/request/${STATE}` });

  expect(response.statusCode).toBe(200);
  expect(response.headers['content-type']).toBe('application/oauth-authz-req+jwt');

  return response.body;
}

describe('GET /auth/request/:state', () => {
  it('serves the stored x509-signed Request Object when no fault is active', async () => {
    const signingJwk = generateSigningJwk();
    const { app, events } = await buildApp({ signingJwk });

    const jwt = await fetchRequestObject(app);

    expect(decodeProtectedHeader(jwt).x5c).toEqual([CERTIFICATE]);
    expect(decodeJwt(jwt).client_id).toBe(NOMINAL_CLIENT_ID);

    // The evidence reports the trust model the wallet was actually served, read
    // back from the artifact rather than from what was intended.
    expect(events.find((event) => event.name === 'rp.request_object.requested')?.diagnostic).toMatchObject({
      clientIdPrefix: 'x509_hash',
      hasX5c: true,
      signingKeyId: SIGNING_KID
    });

    await app.close();
  });

  describe('federation trust model (WP_084)', () => {
    /** The stored artifact of an `openid_federation` engagement: no `x5c`, no
     * inlined Trust Chain, and an entity identifier behind the prefix. */
    async function createStoredFederationRequestObject(signingJwk: JWK): Promise<string> {
      return new SignJWT({
        client_id: `openid_federation:${RP_BASE_URL}`,
        iss: RP_BASE_URL,
        nonce: 'a-nonce',
        response_mode: 'direct_post.jwt',
        response_type: 'vp_token',
        response_uri: `${RP_BASE_URL}/auth/response`,
        state: STATE
      })
        .setProtectedHeader({ alg: 'ES256', kid: SIGNING_KID, typ: 'oauth-authz-req+jwt' })
        .sign(await importJWK(signingJwk, 'ES256'));
    }

    it('serves a Request Object whose only key handle is the federation-published kid', async () => {
      const signingJwk = generateSigningJwk();
      const { app, events } = await buildApp({
        signingJwk,
        storedJwt: await createStoredFederationRequestObject(signingJwk)
      });

      const jwt = await fetchRequestObject(app);
      const header = decodeProtectedHeader(jwt);

      expect(header.x5c, 'the wallet must have no certificate chain to verify with').toBeUndefined();
      expect(header.trust_chain, 'the wallet must have no inlined Entity Configuration either').toBeUndefined();
      expect(header.kid, 'the kid is what the wallet looks up in the federation metadata').toBe(SIGNING_KID);

      const claims = decodeJwt(jwt);
      expect(claims.client_id).toBe(`openid_federation:${RP_BASE_URL}`);
      // WP_086 coherence survives: the identifier behind the prefix is still
      // the Request Object `iss`.
      expect(claims.iss).toBe(RP_BASE_URL);

      // Nothing is defective: the key published in
      // metadata.openid_credential_verifier.jwks verifies it.
      const { d, ...publicJwk } = signingJwk;
      void d;
      await expect(jwtVerify(jwt, await importJWK(publicJwk, 'ES256'))).resolves.toBeDefined();

      // This is the evidence WP_084 matches on: a retrieval that handed the
      // wallet no alternative to the federation metadata.
      expect(events.find((event) => event.name === 'rp.request_object.requested')?.diagnostic).toMatchObject({
        clientIdPrefix: 'openid_federation',
        hasX5c: false,
        signingKeyId: SIGNING_KID
      });

      await app.close();
    });

    it('echoes the wallet_nonce on a POST retrieval without restoring x5c', async () => {
      const signingJwk = generateSigningJwk();
      const { app } = await buildApp({
        signingJwk,
        storedJwt: await createStoredFederationRequestObject(signingJwk)
      });

      const response = await app.inject({
        method: 'POST',
        url: `/auth/request/${STATE}`,
        headers: { 'content-type': 'application/json' },
        payload: { wallet_nonce: 'wallet-provided-nonce' }
      });

      expect(response.statusCode).toBe(200);
      expect(decodeJwt(response.body).wallet_nonce).toBe('wallet-provided-nonce');
      expect(decodeProtectedHeader(response.body).x5c).toBeUndefined();
      expect(decodeJwt(response.body).client_id).toBe(`openid_federation:${RP_BASE_URL}`);

      await app.close();
    });
  });
});
