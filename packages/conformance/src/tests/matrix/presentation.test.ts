import { createHash, generateKeyPairSync } from 'node:crypto';
import { request as httpsRequest } from 'node:https';

import { CompactEncrypt, SignJWT, decodeJwt, decodeProtectedHeader, importJWK, importPKCS8 } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

type JwkKey = Record<string, unknown>;

type InsecureResponse = {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
  text(): Promise<string>;
};

function insecureFetch(
  url: string,
  init?: { body?: string; headers?: Record<string, string>; method?: string; signal?: AbortSignal }
): Promise<InsecureResponse> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = httpsRequest(
      {
        headers: init?.headers,
        hostname: parsed.hostname,
        method: init?.method ?? 'GET',
        path: parsed.pathname + parsed.search,
        port: parsed.port || 443,
        rejectUnauthorized: true
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf-8');
          const status = res.statusCode ?? 0;
          resolve({
            headers: { get: (name) => (res.headers[name.toLowerCase()] as string | undefined) ?? null },
            json: async () => JSON.parse(text) as unknown,
            ok: status >= 200 && status < 300,
            status,
            text: async () => text
          });
        });
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    init?.signal?.addEventListener('abort', () => req.destroy());
    if (init?.body) req.write(init.body);
    req.end();
  });
}

const ALLOWED_JAR_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'];

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
  const encKid = typeof encJwk.kid === 'string' ? encJwk.kid : undefined;
  if (!encKid) {
    throw new Error('Encryption JWK is missing required kid field');
  }

  const { privateKey: holderPrivNode, publicKey: holderPubNode } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const holderPrivJose = await importPKCS8(holderPrivNode.export({ format: 'pem', type: 'pkcs8' }).toString(), 'ES256');
  const holderPubJwk = holderPubNode.export({ format: 'jwk' });

  const { privateKey: issuerPrivNode } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const issuerPrivJose = await importPKCS8(issuerPrivNode.export({ format: 'pem', type: 'pkcs8' }).toString(), 'ES256');

  const issuerJwt = await new SignJWT({
    cnf: { jwk: holderPubJwk },
    iss: 'https://issuer.example.com',
    vct: 'https://credentials.example.com/identity_credential'
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
    .sign(issuerPrivJose);

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

  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      presentation_submission: { definition_id: 'test', descriptor_map: [], id: 'test-submission' },
      state,
      vp_token: { pid: sdJwtWithKb }
    })
  );

  return new CompactEncrypt(plaintext)
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: encKid })
    .encrypt(rpPublicKey);
}

describe.sequential('Relying Party Presentation', () => {
  let rpBaseUrl: string;

  let walletUrl: string;
  let authRequestStatusCode: number;
  let authRequestContentType: string;
  let jarHeader: Record<string, unknown>;
  let jarPayload: Record<string, unknown>;
  let state: string;

  let authResponseStatusCode: number;
  let authResponseContentType: string;
  let authResponseBody: Record<string, unknown>;

  beforeAll(async () => {
    const rawUrl = process.env.ITW_CT_RP_BASE_URL?.trim();
    if (!rawUrl) {
      throw new Error('Missing required env: ITW_CT_RP_BASE_URL');
    }
    rpBaseUrl = rawUrl.replace(/\/$/, '');

    const reqObjRes = await insecureFetch(`${rpBaseUrl}/request-object`, {
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

    const body = (await reqObjRes.json()) as { url: string };
    walletUrl = body.url;
    state = new URL(walletUrl).searchParams.get('state') ?? '';

    const authReqRes = await insecureFetch(`${rpBaseUrl}/auth/request/${state}`, {
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

        const authRes = await insecureFetch(responseUri, {
          body: new URLSearchParams({ response: jwe }).toString(),
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          method: 'POST',
          signal: AbortSignal.timeout(10_000)
        });

        authResponseStatusCode = authRes.status;
        authResponseContentType = authRes.headers.get('content-type') ?? '';
        authResponseBody = (await authRes.json().catch(() => ({}))) as Record<string, unknown>;
      } catch {
        authResponseStatusCode = 0;
        authResponseContentType = '';
        authResponseBody = {};
      }
    } else {
      authResponseStatusCode = 0;
      authResponseContentType = '';
      authResponseBody = {};
    }
  });

  it('[PRESENTATION:AUTHORIZE] RPR-03 - POST /request-object URL contains client_id, request_uri, and state', () => {
    const parsed = new URL(walletUrl);
    expect(
      parsed.searchParams.get('client_id'),
      'Authorization Request URL must contain a non-empty client_id'
    ).toBeTruthy();
    expect(
      parsed.searchParams.get('request_uri'),
      'Authorization Request URL must contain a non-empty request_uri'
    ).toBeTruthy();
    expect(parsed.searchParams.get('state'), 'Authorization Request URL must contain a non-empty state').toBeTruthy();
  });

  it('[PRESENTATION:AUTHORIZE] RPR-08 - GET /auth/request/:state returns HTTP 200', () => {
    expect(authRequestStatusCode, 'Expected GET /auth/request/:state to return HTTP 200').toBe(200);
  });

  it('[PRESENTATION:AUTHORIZE] RPR-89 - GET /auth/request/:state Content-Type is application/oauth-authz-req+jwt', () => {
    expect(authRequestContentType, 'Expected Content-Type to contain application/oauth-authz-req+jwt').toContain(
      'application/oauth-authz-req+jwt'
    );
  });

  it('[PRESENTATION:AUTHORIZE] RPR-89 - JAR header typ is oauth-authz-req+jwt', () => {
    expect(jarHeader.typ, 'Expected JAR protected header typ to be oauth-authz-req+jwt').toBe('oauth-authz-req+jwt');
  });

  it('[PRESENTATION:AUTHORIZE] RPR-88 - JAR signing algorithm is an asymmetric JOSE algorithm', () => {
    expect(
      ALLOWED_JAR_ALGORITHMS,
      `Expected JAR alg "${String(jarHeader.alg)}" to be an asymmetric algorithm (not none or MAC)`
    ).toContain(jarHeader.alg);
  });

  it('[PRESENTATION:AUTHORIZE] RPR-10 - JAR payload contains non-empty client_id', () => {
    expect(typeof jarPayload.client_id, 'client_id must be a string').toBe('string');
    expect((jarPayload.client_id as string).length, 'client_id must not be empty').toBeGreaterThan(0);
  });

  it('[PRESENTATION:AUTHORIZE] RPR-91 - JAR payload response_type is vp_token', () => {
    expect(jarPayload.response_type, 'Expected response_type to be vp_token').toBe('vp_token');
  });

  it('[PRESENTATION:AUTHORIZE] RPR-93 - JAR payload nonce has at least 32 characters', () => {
    expect(typeof jarPayload.nonce, 'nonce must be a string').toBe('string');
    expect(
      (jarPayload.nonce as string).length,
      'nonce must have at least 32 characters to provide sufficient entropy'
    ).toBeGreaterThanOrEqual(32);
  });

  it('[PRESENTATION:AUTHORIZE] RPR-92 - JAR payload contains a non-empty response_uri', () => {
    expect(typeof jarPayload.response_uri, 'response_uri must be a string').toBe('string');
    expect((jarPayload.response_uri as string).length, 'response_uri must not be empty').toBeGreaterThan(0);
  });

  it('[PRESENTATION:AUTHORIZE] RPR-10 - JAR payload contains dcql_query object', () => {
    expect(jarPayload.dcql_query, 'Expected dcql_query to be present and be an object').toBeDefined();
    expect(typeof jarPayload.dcql_query, 'dcql_query must be an object').toBe('object');
  });

  it('[PRESENTATION:AUTHORIZE] RPR-90 - JAR payload response_mode is direct_post.jwt', () => {
    expect(jarPayload.response_mode, 'Expected response_mode to be direct_post.jwt').toBe('direct_post.jwt');
  });

  it('[PRESENTATION:AUTHORIZE] RPR-13 - JAR client_metadata contains an encryption JWK with use=enc', () => {
    const clientMetadata = jarPayload.client_metadata as Record<string, unknown> | undefined;
    expect(clientMetadata, 'client_metadata must be present').toBeDefined();

    const jwks = clientMetadata?.jwks as { keys?: unknown[] } | undefined;
    expect(Array.isArray(jwks?.keys), 'client_metadata.jwks.keys must be an array').toBe(true);

    const encKey = (jwks?.keys as JwkKey[]).find((k) => k.use === 'enc');
    expect(encKey, 'client_metadata.jwks.keys must contain a key with use=enc for response encryption').toBeDefined();
  });

  it('[PRESENTATION:AUTHORIZE] RPR-94 - JAR payload exp is set and is in the future', () => {
    expect(typeof jarPayload.exp, 'exp must be a number').toBe('number');
    const nowSeconds = Math.floor(Date.now() / 1000);
    expect(jarPayload.exp as number, 'JAR exp must be in the future (not expired)').toBeGreaterThan(nowSeconds);
  });

  it('[PRESENTATION:PRESENTATION_RESPONSE] RPR-110 - POST /auth/response with valid JWE returns HTTP 200', () => {
    expect(authResponseStatusCode, 'Expected POST /auth/response to return HTTP 200').toBe(200);
  });

  it('[PRESENTATION:PRESENTATION_RESPONSE] RPR-110 - POST /auth/response response Content-Type is application/json', () => {
    expect(authResponseContentType, 'Expected POST /auth/response Content-Type to contain application/json').toContain(
      'application/json'
    );
  });

  it('[PRESENTATION:PRESENTATION_RESPONSE] RPR-83 - Response body contains a non-empty redirect_uri', () => {
    expect(typeof authResponseBody.redirect_uri, 'redirect_uri must be a string').toBe('string');
    expect((authResponseBody.redirect_uri as string).length, 'redirect_uri must not be empty').toBeGreaterThan(0);
  });

  it('[PRESENTATION:PRESENTATION_RESPONSE] RPR-112 - redirect_uri contains response_code query parameter', () => {
    const redirectUri = new URL(authResponseBody.redirect_uri as string);
    expect(
      redirectUri.searchParams.get('response_code'),
      'redirect_uri must include a response_code query parameter'
    ).not.toBeNull();
  });

  it('[PRESENTATION:PRESENTATION_RESPONSE] RPR-114 - POST /auth/response with invalid JWE returns an HTTP 4xx error response', async () => {
    const reqRes = await insecureFetch(`${rpBaseUrl}/request-object`, {
      body: JSON.stringify({
        dcqlQuery: { credentials: [{ format: 'dc+sd-jwt', id: 'pid' }] },
        flow_type: 'cross-device'
      }),
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
      signal: AbortSignal.timeout(10_000)
    });
    expect(reqRes.ok, 'POST /request-object must succeed for error-path session').toBe(true);

    const { url: freshUrl } = (await reqRes.json()) as { url: string };
    const freshState = new URL(freshUrl).searchParams.get('state') ?? '';

    await insecureFetch(`${rpBaseUrl}/auth/request/${freshState}`, { signal: AbortSignal.timeout(10_000) });

    const responseUri =
      typeof jarPayload.response_uri === 'string' ? jarPayload.response_uri : `${rpBaseUrl}/auth/response`;

    const errRes = await insecureFetch(responseUri, {
      body: new URLSearchParams({ response: 'not.a.valid.jwe.value' }).toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      signal: AbortSignal.timeout(10_000)
    });

    expect(errRes.status, 'Submitting an invalid JWE must return HTTP 4xx (not 200)').toBeGreaterThanOrEqual(400);
  });
});
