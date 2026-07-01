import { createHash, generateKeyPairSync } from 'node:crypto';

import { CompactEncrypt, SignJWT, decodeJwt, decodeProtectedHeader, importJWK, importPKCS8 } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

type JwkKey = Record<string, unknown>;

const ALLOWED_JAR_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];

/**
 * Builds a minimal but fully-valid JARM JWE for the RP's /auth/response endpoint.
 *
 * The VP token is a single dc+sd-jwt credential (no disclosures) bound to a
 * freshly generated holder key, encrypted to the RP's public JWK.
 */
async function buildAuthResponseJwe({
  clientId,
  encJwk,
  nonce,
  state
}: {
  clientId: string;
  encJwk: JwkKey;
  nonce: string;
  state: string;
}): Promise<string> {
  const rpPublicKey = await importJWK(encJwk as Parameters<typeof importJWK>[0]);

  // Holder key pair – P-256, signs the KB-JWT
  const { privateKey: holderPrivNode, publicKey: holderPubNode } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const holderPrivJose = await importPKCS8(holderPrivNode.export({ format: 'pem', type: 'pkcs8' }).toString(), 'ES256');
  const holderPubJwk = holderPubNode.export({ format: 'jwk' });

  // Issuer key pair – P-256, signs the SD-JWT
  const { privateKey: issuerPrivNode } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const issuerPrivJose = await importPKCS8(issuerPrivNode.export({ format: 'pem', type: 'pkcs8' }).toString(), 'ES256');

  // Issuer SD-JWT – no disclosures; cnf binds the holder key
  const issuerJwt = await new SignJWT({
    cnf: { jwk: holderPubJwk },
    iss: 'https://issuer.example.com',
    vct: 'https://credentials.example.com/identity_credential'
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
    .sign(issuerPrivJose);

  // KB-JWT – sd_hash = sha256('') because there are no disclosures
  const sdHash = createHash('sha256').update('').digest('base64url');
  const kbJwt = await new SignJWT({
    aud: clientId,
    iat: Math.floor(Date.now() / 1000),
    nonce,
    sd_hash: sdHash
  })
    .setProtectedHeader({ alg: 'ES256', jwk: holderPubJwk, typ: 'kb+jwt' })
    .sign(holderPrivJose);

  const sdJwtWithKb = `${issuerJwt}~${kbJwt}`;

  // Encrypt as ECDH-ES / A256GCM JWE
  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      presentation_submission: { definition_id: 'test', descriptor_map: [], id: 'test-submission' },
      state,
      vp_token: { pid: sdJwtWithKb }
    })
  );

  return new CompactEncrypt(plaintext).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' }).encrypt(rpPublicKey);
}

describe.sequential('Relying Party Presentation', () => {
  let rpBaseUrl: string;

  // AUTHORIZE shared state
  let authRequestStatusCode: number;
  let authRequestContentType: string;
  let jarHeader: Record<string, unknown>;
  let jarPayload: Record<string, unknown>;
  let state: string;

  // PRESENTATION_RESPONSE shared state
  let authResponseStatusCode: number;
  let authResponseBody: Record<string, unknown>;

  beforeAll(async () => {
    const rawUrl = process.env.ITW_CT_RP_BASE_URL?.trim();
    if (!rawUrl) {
      throw new Error('Missing required env: ITW_CT_RP_BASE_URL');
    }
    rpBaseUrl = rawUrl.replace(/\/$/, '');

    // Step 1: POST /request-object to create an authorization session
    const reqObjRes = await fetch(`${rpBaseUrl}/request-object`, {
      body: JSON.stringify({
        dcqlQuery: { credentials: [{ format: 'dc+sd-jwt', id: 'pid' }] },
        flow_type: 'cross-device'
      }),
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
      signal: AbortSignal.timeout(10_000)
    });

    if (!reqObjRes.ok) {
      throw new Error(`POST /request-object failed with HTTP ${reqObjRes.status}`);
    }

    const { url: walletUrl } = (await reqObjRes.json()) as { url: string };
    state = new URL(walletUrl).searchParams.get('state') ?? '';

    // Step 2: GET /auth/request/:state to fetch the JAR (also transitions session to 'checking')
    const authReqRes = await fetch(`${rpBaseUrl}/auth/request/${state}`, {
      signal: AbortSignal.timeout(10_000)
    });

    authRequestStatusCode = authReqRes.status;
    authRequestContentType = authReqRes.headers.get('content-type') ?? '';
    const jarJwt = await authReqRes.text();

    if (authRequestStatusCode === 200 && jarJwt.length > 0) {
      try {
        jarHeader = decodeProtectedHeader(jarJwt) as Record<string, unknown>;
        jarPayload = decodeJwt(jarJwt) as Record<string, unknown>;
      } catch {
        jarHeader = {};
        jarPayload = {};
      }
    } else {
      jarHeader = {};
      jarPayload = {};
    }

    // Step 3: build and submit a VP token to /auth/response
    const clientMetadata = jarPayload.client_metadata as Record<string, unknown> | undefined;
    const jwks = clientMetadata?.jwks as { keys?: JwkKey[] } | undefined;
    const encJwk = jwks?.keys?.find((k) => k.use === 'enc');

    if (encJwk && typeof jarPayload.nonce === 'string' && typeof jarPayload.client_id === 'string') {
      try {
        const jwe = await buildAuthResponseJwe({
          clientId: jarPayload.client_id,
          encJwk,
          nonce: jarPayload.nonce,
          state
        });

        const responseUri =
          typeof jarPayload.response_uri === 'string' ? jarPayload.response_uri : `${rpBaseUrl}/auth/response`;

        const authRes = await fetch(responseUri, {
          body: new URLSearchParams({ response: jwe }).toString(),
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          method: 'POST',
          signal: AbortSignal.timeout(10_000)
        });

        authResponseStatusCode = authRes.status;
        authResponseBody = (await authRes.json().catch(() => ({}))) as Record<string, unknown>;
      } catch {
        authResponseStatusCode = 0;
        authResponseBody = {};
      }
    } else {
      authResponseStatusCode = 0;
      authResponseBody = {};
    }
  });

  // ── AUTHORIZE step ──────────────────────────────────────────────────────────

  it('[PRESENTATION:AUTHORIZE] RPR-04 - GET /auth/request/:state returns HTTP 200', () => {
    expect(authRequestStatusCode, 'Expected GET /auth/request/:state to return HTTP 200').toBe(200);
  });

  it('[PRESENTATION:AUTHORIZE] RPR-05 - Response Content-Type is application/oauth-authz-req+jwt', () => {
    expect(authRequestContentType, 'Expected Content-Type to contain application/oauth-authz-req+jwt').toContain(
      'application/oauth-authz-req+jwt'
    );
  });

  it('[PRESENTATION:AUTHORIZE] RPR-06 - JAR header typ is oauth-authz-req+jwt', () => {
    expect(jarHeader.typ, 'Expected JAR header.typ to be oauth-authz-req+jwt').toBe('oauth-authz-req+jwt');
  });

  it('[PRESENTATION:AUTHORIZE] RPR-07 - JAR signing algorithm is an allowed JOSE algorithm', () => {
    expect(ALLOWED_JAR_ALGORITHMS, `Expected alg "${String(jarHeader.alg)}" to be in the allowed list`).toContain(
      jarHeader.alg
    );
  });

  it('[PRESENTATION:AUTHORIZE] RPR-08 - JAR payload contains non-empty client_id', () => {
    expect(typeof jarPayload.client_id).toBe('string');
    expect((jarPayload.client_id as string).length, 'client_id must not be empty').toBeGreaterThan(0);
  });

  it('[PRESENTATION:AUTHORIZE] RPR-09 - JAR payload response_type is vp_token', () => {
    expect(jarPayload.response_type, 'Expected response_type to be vp_token').toBe('vp_token');
  });

  it('[PRESENTATION:AUTHORIZE] RPR-10 - JAR payload contains non-empty nonce', () => {
    expect(typeof jarPayload.nonce).toBe('string');
    expect((jarPayload.nonce as string).length, 'nonce must not be empty').toBeGreaterThan(0);
  });

  it('[PRESENTATION:AUTHORIZE] RPR-11 - JAR payload contains response_uri', () => {
    expect(typeof jarPayload.response_uri).toBe('string');
    expect((jarPayload.response_uri as string).length, 'response_uri must not be empty').toBeGreaterThan(0);
  });

  it('[PRESENTATION:AUTHORIZE] RPR-12 - JAR payload contains dcql_query', () => {
    expect(jarPayload.dcql_query, 'Expected dcql_query to be an object').toBeDefined();
    expect(typeof jarPayload.dcql_query).toBe('object');
  });

  it('[PRESENTATION:AUTHORIZE] RPR-13 - JAR payload response_mode is direct_post.jwt', () => {
    expect(jarPayload.response_mode, 'Expected response_mode to be direct_post.jwt').toBe('direct_post.jwt');
  });

  it('[PRESENTATION:AUTHORIZE] RPR-14 - JAR client_metadata contains an encryption JWK with use=enc', () => {
    const clientMetadata = jarPayload.client_metadata as Record<string, unknown> | undefined;
    expect(clientMetadata, 'client_metadata must be present').toBeDefined();

    const jwks = clientMetadata?.jwks as { keys?: unknown[] } | undefined;
    expect(Array.isArray(jwks?.keys), 'client_metadata.jwks.keys must be an array').toBe(true);

    const encKey = (jwks?.keys as JwkKey[]).find((k) => k.use === 'enc');
    expect(encKey, 'client_metadata.jwks.keys must contain a key with use=enc').toBeDefined();
  });

  // ── PRESENTATION_RESPONSE step ──────────────────────────────────────────────

  it('[PRESENTATION:PRESENTATION_RESPONSE] RPR-15 - POST /auth/response with valid JWE returns HTTP 200', () => {
    expect(authResponseStatusCode, 'Expected POST /auth/response to return HTTP 200').toBe(200);
  });

  it('[PRESENTATION:PRESENTATION_RESPONSE] RPR-16 - Response body contains redirect_uri', () => {
    expect(typeof authResponseBody.redirect_uri, 'Expected redirect_uri to be a string').toBe('string');
    expect((authResponseBody.redirect_uri as string).length, 'redirect_uri must not be empty').toBeGreaterThan(0);
  });

  it('[PRESENTATION:PRESENTATION_RESPONSE] RPR-17 - redirect_uri contains response_code query parameter', () => {
    const redirectUri = new URL(authResponseBody.redirect_uri as string);
    expect(
      redirectUri.searchParams.get('response_code'),
      'redirect_uri must include a response_code query parameter'
    ).not.toBeNull();
  });
});
