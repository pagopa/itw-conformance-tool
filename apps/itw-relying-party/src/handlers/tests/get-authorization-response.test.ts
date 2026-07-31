import { createX509HashClientId } from '@pagopa/io-wallet-oid4vp';
import Fastify from 'fastify';
import { CompactEncrypt, importJWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import authorizationResponseRoute from '../../routes/authorization-response.js';
import { callbacks as partialCallbacks, getDecryptJweCallback } from '../../utils/crypto.js';
import {
  createCertificateBase64Der,
  createSdJwtPresentation,
  CREDENTIAL_ID,
  DCQL_QUERY,
  DISCLOSED_CLAIMS,
  generateEcJwk,
  PRESENTATION_NONCE,
  toPublicJwk
} from '../../utils/tests/fixtures/presentation.js';

import type { ObservedEvent } from '@itw-conformance-tool/conformance';
import type { JWK } from 'jose';

const RP_BASE_URL = 'https://rp.example.org';
const SESSION_ID = '11111111-2222-4333-8444-555555555555';
const STATE = '99999999-8888-4777-8666-555555555555';

type FlowType = 'cross-device' | 'same-device';

interface UpdateCall {
  redirectUri?: string;
  state: string;
  status: string;
  values?: unknown;
}

/**
 * Boots the real response route decorated with only what the handler reads, and
 * with a real ECDH-ES decryption callback so an encrypted Authorization
 * Response travels the genuine path.
 */
async function buildApp(flowType: FlowType) {
  const app = Fastify();
  const events: ObservedEvent[] = [];
  const updates: UpdateCall[] = [];

  const encryptionJwk = generateEcJwk({ alg: 'ECDH-ES', kid: 'rp-enc-key', use: 'enc' });
  const requestSigningJwk = generateEcJwk({ alg: 'ES256', kid: 'rp-signing-key', use: 'sig' });
  const clientId = await createX509HashClientId({
    certificateChain: [await createCertificateBase64Der(requestSigningJwk)],
    hash: partialCallbacks.hash
  });

  // The stored Request Object. The handler decodes it without verifying, but
  // the SDK reads `client_metadata.jwks` out of it to pick the decryption key.
  const requestObjectJwt = await new SignJWT({
    client_id: clientId,
    client_metadata: { jwks: { keys: [toPublicJwk(encryptionJwk)] } },
    dcql_query: DCQL_QUERY,
    iss: RP_BASE_URL,
    nonce: PRESENTATION_NONCE,
    response_mode: 'direct_post.jwt',
    response_type: 'vp_token',
    response_uri: `${RP_BASE_URL}/auth/response?session_id=${SESSION_ID}`,
    state: STATE
  })
    .setProtectedHeader({ alg: 'ES256', kid: requestSigningJwk.kid, typ: 'oauth-authz-req+jwt' })
    .sign(await importJWK(requestSigningJwk, 'ES256'));

  app.decorate('config', { BASE_URL: RP_BASE_URL, IACA_X509: '' });
  app.decorate('jwks', { enc: { private: encryptionJwk, public: toPublicJwk(encryptionJwk) } });
  app.decorate('callbacks', { ...partialCallbacks, decryptJwe: getDecryptJweCallback(encryptionJwk as never), fetch });
  app.decorate('repository', {
    requestObject: {
      getBySessionId: () => ({ flowType, id: STATE, jwt: requestObjectJwt }),
      update: (state: string, status: string, redirectUri?: string, values?: unknown) =>
        updates.push({ redirectUri, state, status, values })
    }
  });
  app.decorate('conformanceEventSink', {
    emit: async (event: ObservedEvent) => {
      events.push(event);
    }
  });

  await app.register(authorizationResponseRoute);
  await app.ready();

  return { app, clientId, encryptionJwk, events, updates };
}

/** Encrypts the Authorization Response exactly as a wallet does for direct_post.jwt. */
async function encryptResponse(payload: unknown, encryptionJwk: JWK & { kid: string }): Promise<string> {
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: encryptionJwk.kid })
    .encrypt(await importJWK(toPublicJwk(encryptionJwk), 'ECDH-ES'));
}

async function postResponse(flowType: FlowType) {
  const context = await buildApp(flowType);

  const response = await context.app.inject({
    method: 'POST',
    url: `/auth/response?session_id=${SESSION_ID}`,
    headers: { 'content-type': 'application/json' },
    payload: {
      response: await encryptResponse(
        {
          state: STATE,
          vp_token: {
            [CREDENTIAL_ID]: [await createSdJwtPresentation({ audience: RP_BASE_URL })]
          }
        },
        toPublicJwk(context.encryptionJwk) as JWK & { kid: string }
      )
    }
  });

  await context.app.close();

  return { ...context, response };
}

describe('POST /auth/response — successful presentation', () => {
  it('returns the redirect_uri in the same-device flow', async () => {
    const { response, updates } = await postResponse('same-device');

    expect(response.statusCode, response.body).toBe(200);
    const body = response.json() as { redirect_uri?: string };
    expect(body.redirect_uri).toMatch(new RegExp(`^${RP_BASE_URL}/callback\\?state=${STATE}&response_code=[a-f0-9]+$`));

    expect(updates).toEqual([
      { redirectUri: body.redirect_uri, state: STATE, status: 'verified', values: [DISCLOSED_CLAIMS] }
    ]);
  });

  it('withholds the redirect_uri in the cross-device flow', async () => {
    // A returned redirect_uri instructs the wallet to send its user-agent there,
    // and in cross-device the browser that started the flow is on another
    // device. It reaches the same destination by polling /status instead.
    const { response } = await postResponse('cross-device');

    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toEqual({});
  });

  it('still stores the redirect_uri in the cross-device flow', async () => {
    // /status and /callback both resolve the session through the response_code
    // embedded in it, so it has to exist even when it is not handed back.
    const { updates } = await postResponse('cross-device');

    expect(updates[0].status).toBe('verified');
    expect(updates[0].redirectUri).toMatch(new RegExp(`^${RP_BASE_URL}/callback\\?state=${STATE}&response_code=`));
  });

  it('acknowledges with JSON and forbids caching', async () => {
    const { response } = await postResponse('same-device');

    expect(response.headers['content-type']).toMatch(/application\/json/);
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it('reports the audience evidence the key binding checks rest on', async () => {
    const { clientId, events } = await postResponse('same-device');

    const succeeded = events.find((event) => event.name === 'vp_token.validation.succeeded');
    expect(succeeded?.diagnostic).toMatchObject({
      // The entity identifier, not the certificate hash: this is the value IT
      // Wallet requires the key binding `aud` to carry.
      acceptedKeyBindingAudiences: [RP_BASE_URL, clientId],
      clientId: RP_BASE_URL,
      clientIdPrefixed: clientId,
      flowType: 'same-device',
      keyBindingAudiences: [{ aud: RP_BASE_URL, credentialId: CREDENTIAL_ID, form: 'entity-identifier' }],
      redirectUriReturned: true,
      requestObjectState: STATE,
      state: STATE
    });
  });

  it('records that no redirect_uri was returned for cross-device', async () => {
    const { events } = await postResponse('cross-device');

    const succeeded = events.find((event) => event.name === 'vp_token.validation.succeeded');
    expect(succeeded?.diagnostic).toMatchObject({ flowType: 'cross-device', redirectUriReturned: false });
  });
});

describe('POST /auth/response — authorization error response', () => {
  async function postError() {
    const { app, events, updates } = await buildApp('same-device');

    const response = await app.inject({
      method: 'POST',
      url: `/auth/response?session_id=${SESSION_ID}`,
      headers: { 'content-type': 'application/json' },
      payload: { error: 'access_denied', error_description: 'user refused', state: STATE }
    });

    await app.close();

    return { events, response, updates };
  }

  it('acknowledges with a JSON object body, not an empty one', async () => {
    // A response endpoint that has processed an authorization error response
    // must acknowledge it exactly as it would a successful one, or a wallet
    // cannot tell acknowledgement from a truncated response.
    const { response } = await postError();

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toMatch(/application\/json/);
    expect(response.body).not.toBe('');
    expect(response.json()).toEqual({});
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it('marks the session rejected and reports the error', async () => {
    const { events, updates } = await postError();

    expect(updates).toEqual([{ redirectUri: undefined, state: STATE, status: 'rejected', values: undefined }]);

    const reported = events.find((event) => event.name === 'rp.presentation_error.received');
    expect(reported?.diagnostic).toMatchObject({
      endpoint: '/auth/response',
      error: 'access_denied',
      errorDescription: 'user refused',
      method: 'POST'
    });
  });

  it('does not emit a successful verification', async () => {
    const { events } = await postError();

    expect(events.find((event) => event.name === 'vp_token.validation.succeeded')).toBeUndefined();
  });
});

describe('POST /auth/response — rejected presentation', () => {
  it('answers 403 when the key binding audience is wrong', async () => {
    const context = await buildApp('same-device');

    const response = await context.app.inject({
      method: 'POST',
      url: `/auth/response?session_id=${SESSION_ID}`,
      headers: { 'content-type': 'application/json' },
      payload: {
        response: await encryptResponse(
          {
            state: STATE,
            vp_token: {
              [CREDENTIAL_ID]: [await createSdJwtPresentation({ audience: 'https://attacker.example.org' })]
            }
          },
          toPublicJwk(context.encryptionJwk) as JWK & { kid: string }
        )
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: 'invalid_request' });
    expect(context.updates.map((update) => update.status)).toEqual(['rejected']);

    await context.app.close();
  });
});

describe('POST /auth/response — response encryption', () => {
  it('rejects a signed-but-unencrypted Authorization Response', async () => {
    // IT Wallet 1.4 raises response encryption from SHOULD to MUST. The SDK's
    // JARM verifier accepts a signed-only response — it rejects only one that is
    // neither signed nor encrypted — so without the check in the handler this
    // presentation would be processed normally.
    const context = await buildApp('same-device');
    const walletJwk = generateEcJwk({ alg: 'ES256', kid: 'wallet-signing-key', use: 'sig' });
    const now = Math.floor(Date.now() / 1000);

    const signedResponse = await new SignJWT({
      aud: context.clientId,
      exp: now + 300,
      iss: RP_BASE_URL,
      state: STATE,
      vp_token: {
        [CREDENTIAL_ID]: [await createSdJwtPresentation({ audience: RP_BASE_URL })]
      }
    })
      .setProtectedHeader({ alg: 'ES256', jwk: toPublicJwk(walletJwk), kid: walletJwk.kid })
      .sign(await importJWK(walletJwk, 'ES256'));

    const response = await context.app.inject({
      method: 'POST',
      url: `/auth/response?session_id=${SESSION_ID}`,
      headers: { 'content-type': 'application/json' },
      payload: { response: signedResponse }
    });

    expect(response.statusCode, response.body).toBe(400);
    expect(response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('must be encrypted')
    });
    expect(context.updates.map((update) => update.status)).toEqual(['rejected']);

    const failure = context.events.find((event) => event.name === 'vp_token.validation.failed');
    expect(failure, 'the refusal must be observable as evidence').toBeDefined();

    await context.app.close();
  });
});

describe('POST /auth/response — session identity', () => {
  it('uses a fresh response_code per presentation', async () => {
    const [first, second] = await Promise.all([postResponse('same-device'), postResponse('same-device')]);

    const codeOf = (body: unknown) =>
      new URL((body as { redirect_uri: string }).redirect_uri).searchParams.get('response_code');

    expect(codeOf(first.response.json())).not.toBe(codeOf(second.response.json()));
  });

  it('mints a response_code with at least 128 bits of entropy', async () => {
    const { response } = await postResponse('same-device');
    const code = new URL((response.json() as { redirect_uri: string }).redirect_uri).searchParams.get('response_code');

    expect(code).toMatch(/^[a-f0-9]{64}$/);
  });
});
