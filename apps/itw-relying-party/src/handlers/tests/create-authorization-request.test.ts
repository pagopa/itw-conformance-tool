import { createHash, createPrivateKey, generateKeyPairSync, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type Server } from 'node:https';
import { type AddressInfo } from 'node:net';

import FastifySensible from '@fastify/sensible';
import { convertPemToBase64Der, createSelfSignedCertificateFromJwk } from '@itw-conformance-tool/crypto';
import { INTERNAL_SERVICE_REQUEST_HEADER } from '@itw-conformance-tool/utils';
import { validateTrustChain } from '@pagopa/io-wallet-oid-federation';
import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import Fastify from 'fastify';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { createRpFaultStore } from '../../faults/rp-fault-store.js';
import authorizationRequestRoute from '../../routes/authorization-request.js';
import { callbacks as partialCallbacks, getEncryptJweCallback, getSignJwtCallback } from '../../utils/crypto.js';

import type { RpFaultProfile } from '@itw-conformance-tool/faults';
import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { JWK } from 'jose';

const RP_BASE_URL = 'https://rp.example.org';
const SIGNING_KID = 'rp-signing-key';
const FEDERATION_KID = 'rp-federation-key';
const TRUST_ANCHOR_KID = 'ta-federation-key';

const DCQL_QUERY = {
  credentials: [
    {
      id: 'pid',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['urn:eudi:pid:it:1'] },
      claims: [{ path: ['given_name'] }]
    }
  ]
};

function generateJwk(use: 'enc' | 'sig'): JWK & { kid: string } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' }) as JWK;

  return use === 'sig'
    ? { ...jwk, alg: 'ES256', kid: SIGNING_KID, use: 'sig' }
    : { ...jwk, alg: 'ECDH-ES+A256KW', kid: 'rp-encryption-key', use: 'enc' };
}

function toPublicJwk(jwk: JWK & { kid: string }): JWK & { kid: string } {
  const { d: _d, ...publicJwk } = jwk;

  return publicJwk as JWK & { kid: string };
}

function generateFederationJwk(kid: string): JWK & { kid: string } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

  return { ...(privateKey.export({ format: 'jwk' }) as JWK), alg: 'ES256', kid, use: 'sig' };
}

/** Signs an entity statement the way both federation participants do. */
async function signEntityStatement(
  signingJwk: JWK & { kid: string },
  claims: Record<string, unknown>
): Promise<string> {
  const issuedAt = Math.floor(Date.now() / 1000);

  return new SignJWT({ ...claims, exp: issuedAt + 3600, iat: issuedAt })
    .setProtectedHeader({ alg: 'ES256', kid: signingJwk.kid, typ: 'entity-statement+jwt' })
    .sign(await importJWK(signingJwk, 'ES256'));
}

interface TrustAnchorStub {
  close(): Promise<void>;
  /** Headers of every request the Relying Party made, by path. */
  requests: { headers: Record<string, string | string[] | undefined>; url: string }[];
  federationJwk: JWK & { kid: string };
  url: string;
}

/**
 * A stand-in Trust Anchor serving the two statements the Relying Party cannot
 * sign for itself: the Subordinate Statement about the Relying Party, and its
 * own Entity Configuration. It runs over TLS on a throwaway self-signed
 * certificate, exactly like the real one.
 */
async function startTrustAnchorStub(relyingPartyFederationJwk: JWK & { kid: string }): Promise<TrustAnchorStub> {
  const federationJwk = generateFederationJwk(TRUST_ANCHOR_KID);
  const tlsJwk = generateFederationJwk('tls');
  const requests: TrustAnchorStub['requests'] = [];

  const server = createServer(
    {
      cert: await createSelfSignedCertificateFromJwk(tlsJwk),
      key: createPrivateKey({ key: tlsJwk as JWK, format: 'jwk' }).export({ format: 'pem', type: 'pkcs8' })
    },
    (request, response) => {
      requests.push({ headers: request.headers, url: request.url ?? '' });

      const url = new URL(request.url ?? '/', 'https://trust-anchor.invalid');
      const entityId = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;

      const statement =
        url.pathname === '/fetch'
          ? signEntityStatement(federationJwk, {
              iss: entityId,
              jwks: { keys: [toPublicJwk(relyingPartyFederationJwk)] },
              sub: url.searchParams.get('sub')
            })
          : url.pathname === '/.well-known/openid-federation'
            ? signEntityStatement(federationJwk, {
                iss: entityId,
                jwks: { keys: [toPublicJwk(federationJwk)] },
                sub: entityId
              })
            : undefined;

      if (!statement) {
        response.writeHead(404).end();
        return;
      }

      void statement.then((jwt) =>
        response.writeHead(200, { 'content-type': 'application/entity-statement+jwt' }).end(jwt)
      );
    }
  );

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  return {
    close: async () => {
      server.close();
      await once(server as Server, 'close');
    },
    requests,
    federationJwk,
    url: `https://127.0.0.1:${(server.address() as AddressInfo).port}`
  };
}

/** Boots the real route with the real fault store, decorated with only what the
 * handler reads. Mirrors the sibling Request Object route tests. */
async function buildApp(
  options: { fault?: RpFaultProfile; federationJwk?: JWK & { kid: string }; trustAnchorUrl?: string } = {}
) {
  const app = Fastify();
  const rpFaultStore = createRpFaultStore();

  if (options.fault) {
    const activation = rpFaultStore.activate({
      scenarioId: `test-${randomUUID()}`,
      specVersion: '1.4',
      profile: options.fault
    });
    expect(activation, 'the fault profile must be activatable at spec version 1.4').toEqual({ ok: true });
  }

  const signingJwk = generateJwk('sig');
  const encryptionJwk = generateJwk('enc');
  const federationJwk = options.federationJwk ?? generateFederationJwk(FEDERATION_KID);
  const storedRequestObjects: { id: string; jwt: string }[] = [];

  // The SDK parses the `x5c` entry it is handed, so the certificate has to be a
  // real one for this key.
  const certificate = convertPemToBase64Der(await createSelfSignedCertificateFromJwk(signingJwk));

  app.decorate('config', {
    BASE_URL: RP_BASE_URL,
    RP_X509: certificate,
    TRUST_ANCHOR_URL: options.trustAnchorUrl ?? 'https://ta.example.org'
  });
  app.decorate('jwks', {
    enc: { private: encryptionJwk, public: toPublicJwk(encryptionJwk) },
    federation: { private: federationJwk, public: toPublicJwk(federationJwk) },
    sig: { private: signingJwk, public: toPublicJwk(signingJwk) }
  });
  app.decorate('callbacks', {
    ...partialCallbacks,
    encryptJwe: getEncryptJweCallback(toPublicJwk(encryptionJwk) as Jwk),
    fetch,
    signJwt: getSignJwtCallback([signingJwk as Jwk])
  });
  app.decorate('sdkConfig', new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_4 }));
  app.decorate('repository', {
    nonce: { insert: () => undefined },
    requestObject: {
      insert: (entry: { id: string; jwt: string }) => storedRequestObjects.push(entry)
    }
  });
  app.decorate('rpFaultStore', rpFaultStore);

  // The handler answers malformed queries and an unreachable Trust Anchor with
  // sensible's HTTP error helpers, exactly as the booted app does.
  await app.register(FastifySensible);
  await app.register(authorizationRequestRoute);
  await app.ready();

  return { app, federationJwk, signingJwk, storedRequestObjects };
}

async function createEngagement(
  options: {
    clientIdPrefix?: 'openid_federation' | 'x509_hash';
    fault?: RpFaultProfile;
    federationJwk?: JWK & { kid: string };
    includeTrustChain?: boolean;
    trustAnchorUrl?: string;
  } = {}
) {
  const { app, federationJwk, signingJwk, storedRequestObjects } = await buildApp(options);

  const response = await app.inject({
    method: 'POST',
    url: '/create-authorization-request',
    payload: {
      dcqlQuery: DCQL_QUERY,
      flow_type: 'cross-device',
      wallet_auth_base_uri: 'openid4vp://',
      ...(options.clientIdPrefix ? { client_id_prefix: options.clientIdPrefix } : {}),
      ...(options.includeTrustChain ? { include_trust_chain: true } : {})
    }
  });

  expect(response.statusCode, response.body).toBe(200);
  const engagementClientId = new URL((response.json() as { url: string }).url).searchParams.get('client_id');
  const requestObject = decodeJwt(storedRequestObjects[0].jwt);

  await app.close();

  return {
    engagementClientId,
    federationJwk,
    header: decodeProtectedHeader(storedRequestObjects[0].jwt),
    requestObject,
    signingJwk,
    storedRequestObject: storedRequestObjects[0],
    storedClientId: requestObject.client_id
  };
}

describe('POST /create-authorization-request', () => {
  it('defaults to the x509_hash client identifier in both the engagement and the Request Object', async () => {
    const { engagementClientId, header, storedClientId } = await createEngagement();

    // The identifier behind the prefix is a hash, never a URL: a wallet resolves
    // it by hashing the leaf certificate it was handed in `x5c`.
    const x5c = (header.x5c as string[])[0];
    const expectedThumbprint = createHash('sha256').update(Buffer.from(x5c, 'base64')).digest('base64url');

    expect(engagementClientId).toBe(`x509_hash:${expectedThumbprint}`);
    expect(engagementClientId, 'the identifier must not be the entity URL').not.toBe(`x509_hash:${RP_BASE_URL}`);
    // OpenID4VP requires the two to be identical, including the prefix.
    expect(engagementClientId).toBe(storedClientId);
  });

  it('advertises only what the Verifier can process, and no self-attested endpoint lists', async () => {
    const { requestObject } = await createEngagement();
    const clientMetadata = requestObject.client_metadata as Record<string, unknown>;

    // Attested endpoint lists belong to the Entity Configuration. A copy the
    // Relying Party signs into its own Request Object attests nothing, and a
    // wallet trusting it would silently pass WP_081 and WP_091a.
    expect(clientMetadata.request_uris).toBeUndefined();
    expect(clientMetadata.response_uris).toBeUndefined();

    // IT Wallet mandates AES-GCM for the encrypted response; A256GCM leads.
    expect(clientMetadata.encrypted_response_enc_values_supported).toEqual(['A256GCM', 'A128GCM']);

    // VpTokenVerifier implements dc+sd-jwt over ES256 and nothing else.
    expect(clientMetadata.vp_formats_supported).toEqual({
      'dc+sd-jwt': { 'kb-jwt_alg_values': ['ES256'], 'sd-jwt_alg_values': ['ES256'] }
    });
  });

  it('serves the federation trust model when the caller asks for the openid_federation prefix', async () => {
    const { engagementClientId, header, requestObject, signingJwk, storedRequestObject, storedClientId } =
      await createEngagement({
        clientIdPrefix: 'openid_federation'
      });

    // The prefix carries the entity identifier itself — that is what points the
    // wallet at the Trust Chain — and both copies must still agree.
    expect(engagementClientId).toBe(`openid_federation:${RP_BASE_URL}`);
    expect(storedClientId).toBe(engagementClientId);
    expect(requestObject.iss, 'the identifier behind the prefix is the Entity Configuration sub').toBe(RP_BASE_URL);

    // Both non-federation key sources are gone, so the header `kid` is the only
    // handle a wallet has on the signing key (WP_084).
    expect(header.x5c, 'the certificate chain is the key source this trust model removes').toBeUndefined();
    expect(header.trust_chain, 'an inlined Trust Chain would carry the Entity Configuration into the header').toBe(
      undefined
    );
    expect(header.kid).toBe(SIGNING_KID);

    // Nothing is defective: the key a wallet resolves by that `kid` from
    // metadata.openid_credential_verifier.jwks is the public half of the key
    // that signed it. Only the key discovery path differs from the x509 flow.
    await expect(
      jwtVerify(storedRequestObject.jwt, await importJWK(toPublicJwk(signingJwk), 'ES256'))
    ).resolves.toBeDefined();
  });

  it('keeps the x509_hash trust model intact when no prefix is asked for', async () => {
    const { header } = await createEngagement();

    expect(header.x5c, 'the x509_hash prefix commits to the certificate chain in the header').toBeDefined();
  });

  it('inlines a Trust Chain that resolves the Relying Party up to the Trust Anchor', async () => {
    const relyingPartyFederationJwk = generateFederationJwk(FEDERATION_KID);
    const trustAnchor = await startTrustAnchorStub(relyingPartyFederationJwk);

    try {
      const { header, storedRequestObject } = await createEngagement({
        clientIdPrefix: 'openid_federation',
        federationJwk: relyingPartyFederationJwk,
        includeTrustChain: true,
        trustAnchorUrl: trustAnchor.url
      });

      const trustChain = header.trust_chain as string[];

      // OpenID Federation fixes the order: the leaf first, the Trust Anchor's own
      // Entity Configuration last, one Subordinate Statement between them.
      expect(trustChain).toHaveLength(3);

      const [relyingPartyEntityConfiguration, subordinateStatement, trustAnchorEntityConfiguration] = trustChain;
      expect(decodeJwt(relyingPartyEntityConfiguration).sub, 'the leaf is this Relying Party').toBe(RP_BASE_URL);
      expect(decodeJwt(subordinateStatement).sub, 'the Trust Anchor attests this Relying Party').toBe(RP_BASE_URL);
      expect(decodeJwt(trustAnchorEntityConfiguration).sub).toBe(trustAnchor.url);

      // Every signature, expiry and `iss`/`sub` link checked the way a wallet
      // checks them, and the root bound to the Trust Anchor the engagement
      // belongs to — a chain that merely looks well shaped would pass none of it.
      await expect(
        validateTrustChain(trustChain, {
          callbacks: { fetch, hash: partialCallbacks.hash, verifyJwt: partialCallbacks.verifyJwt },
          trustAnchorUrls: [trustAnchor.url]
        })
      ).resolves.toBeUndefined();

      // And the chain has to be about the Request Object it travels in: the key
      // its `kid` names is published by the leaf statement it carries.
      const verifierKeys = (
        decodeJwt(relyingPartyEntityConfiguration).metadata as {
          openid_credential_verifier: { jwks: { keys: JWK[] } };
        }
      ).openid_credential_verifier.jwks.keys;
      expect(verifierKeys.map((key) => key.kid)).toContain(header.kid);
      await expect(
        jwtVerify(storedRequestObject.jwt, createLocalJWKSet({ keys: verifierKeys }))
      ).resolves.toBeDefined();

      // The wallet never made these calls, so they must not be recorded as
      // Trust Chain resolution evidence against it.
      expect(trustAnchor.requests.map(({ url }) => url.split('?')[0])).toEqual(
        expect.arrayContaining(['/fetch', '/.well-known/openid-federation'])
      );
      for (const { headers } of trustAnchor.requests) {
        expect(headers[INTERNAL_SERVICE_REQUEST_HEADER]).toBeDefined();
      }
    } finally {
      await trustAnchor.close();
    }
  });

  it('refuses the engagement when the Trust Chain it promised cannot be assembled', async () => {
    const { app } = await buildApp({ trustAnchorUrl: 'https://127.0.0.1:1' });

    const response = await app.inject({
      method: 'POST',
      url: '/create-authorization-request',
      payload: {
        client_id_prefix: 'openid_federation',
        dcqlQuery: DCQL_QUERY,
        flow_type: 'cross-device',
        include_trust_chain: true,
        wallet_auth_base_uri: 'openid4vp://'
      }
    });

    // Half a Trust Chain is a defect no scenario asked for, so no engagement is
    // handed out at all.
    expect(response.statusCode).toBe(502);

    await app.close();
  });

  it('keeps the client identifier untouched by faults that do not rewrite it', async () => {
    const { engagementClientId, storedClientId } = await createEngagement({
      fault: { type: 'request-object-invalid-client-id' }
    });

    expect(engagementClientId).toMatch(/^x509_hash:[A-Za-z0-9_-]+$/);
    expect(engagementClientId).toBe(storedClientId);
  });
});
