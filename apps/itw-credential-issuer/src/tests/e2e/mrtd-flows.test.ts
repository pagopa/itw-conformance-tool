import crypto from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importPKCS8, SignJWT } from 'jose';
import { afterEach, describe, expect, it } from 'vitest';

import { generateIaca, generateJwks } from '../../crypto/auto-keygen.js';
import conformanceHooks from '../../hooks/conformance.js';
import configPlugin from '../../plugins/config.js';
import dbPlugin from '../../plugins/db.js';
import corsPlugin, { autoConfig as corsConfig } from '../../plugins/external/cors.js';
import formbodyPlugin from '../../plugins/external/formbody.js';
import helmetPlugin, { autoConfig as helmetConfig } from '../../plugins/external/helmet.js';
import rateLimitPlugin, { autoConfig as rateLimitConfig } from '../../plugins/external/rate-limit.js';
import sensiblePlugin from '../../plugins/external/sensible.js';
import keysPlugin from '../../plugins/keys.js';
import authorizeRoute from '../../routes/authorize.js';
import codeJwtRoute from '../../routes/code-jwt.js';
import credentialRoute from '../../routes/credential.js';
import edocProofRoute from '../../routes/edoc-proof.js';
import edocRoute from '../../routes/edoc.js';
import idpCallbackRoute from '../../routes/idp-callback.js';
import mockIdpRoute from '../../routes/mock-idp.js';
import nonceRoute from '../../routes/nonce.js';
import parRoute from '../../routes/par.js';
import presentationResponseRoute from '../../routes/presentation-response.js';
import tokenRoute from '../../routes/token.js';

import type { FastifyInstance } from 'fastify';

const REDIRECT_URI = 'https://example.com/callback';

const STATE = 'e2e-state-123';

const CODE_VERIFIER = 'this-is-a-very-secret-code-verifier';

const CODE_CHALLENGE = crypto.createHash('sha256').update(CODE_VERIFIER).digest('base64url');

const ENV_KEYS = ['DATA_DIR', 'PORT', 'HOST', 'DB_CLEANUP_INTERVAL_MS', 'AUTH_FLOW'] as const;

async function setupKeyMaterial(): Promise<string> {
  const rootDir = mkdtempSync(path.join(tmpdir(), 'issuer-e2e-mrtd-'));

  const issuerDir = path.join(rootDir, 'issuer');

  mkdirSync(issuerDir);

  const [jwksJson, iaca] = await Promise.all([generateJwks(), generateIaca()]);

  writeFileSync(path.join(issuerDir, 'signing-keys.jwks.json'), jwksJson);

  writeFileSync(path.join(issuerDir, 'iaca-cert.pem'), iaca.certPem);

  writeFileSync(path.join(issuerDir, 'iaca-key.pem'), iaca.keyPem);

  return rootDir;
}

async function createApp(authFlow: 'direct' | 'l2plus' | 'l3'): Promise<FastifyInstance> {
  process.env.DATA_DIR = await setupKeyMaterial();

  process.env.DB_CLEANUP_INTERVAL_MS = '999999';

  process.env.AUTH_FLOW = authFlow;

  /**
   * IMPORTANT:
   * deterministic origin for DPoP HTU
   */
  process.env.HOST = '127.0.0.1';
  process.env.PORT = '3000';

  const app = Fastify({
    logger: false
  });

  await app.register(configPlugin);
  await app.register(dbPlugin);
  await app.register(keysPlugin);
  await app.register(conformanceHooks);
  await app.register(corsPlugin, corsConfig);
  await app.register(helmetPlugin, helmetConfig);
  await app.register(formbodyPlugin);
  await app.register(rateLimitPlugin, rateLimitConfig);
  await app.register(sensiblePlugin);

  await app.register(parRoute);
  await app.register(authorizeRoute);
  await app.register(mockIdpRoute);
  await app.register(edocRoute);
  await app.register(edocProofRoute);
  await app.register(idpCallbackRoute);
  await app.register(presentationResponseRoute);
  await app.register(codeJwtRoute);
  await app.register(tokenRoute);
  await app.register(nonceRoute);
  await app.register(credentialRoute);

  await app.ready();

  return app;
}

function getAppBaseUrl(): string {
  return 'http://127.0.0.1:3000';
}

async function buildWallet() {
  const { privateKey, publicKey } = await generateKeyPair('ES256');

  const pureJwk = await exportJWK(publicKey);

  const clientId = await calculateJwkThumbprint(pureJwk, 'sha256');

  pureJwk.kid = clientId;

  const walletPublicJwk = {
    ...pureJwk,
    alg: 'ES256',
    kid: clientId
  };

  return {
    privateKey,
    pureJwk,
    clientId,
    walletPublicJwk
  };
}

async function getAttestations(wallet: any, audience: string, clientId: string, isV13: boolean) {

  const attestationJwt = isV13
    ? await (async () => {
        const providerMaterial = await generateIaca();
        const cleanCert = providerMaterial.certPem
          .replace(/-----\s*BEGIN CERTIFICATE\s*-----/, '')
          .replace(/-----\s*END CERTIFICATE\s*-----/, '')
          .replace(/\s/g, '');
        const providerPrivateKey = await importPKCS8(providerMaterial.keyPem, 'ES256');

        return new SignJWT({
          cnf: { jwk: wallet.walletPublicJwk },
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          iss: 'https://wallet-provider.example',
          status: {
            status_list: {
              idx: 0,
              uri: 'https://wallet-provider.example/statuslist'
            }
          },
          sub: clientId
        })
          .setProtectedHeader({
            alg: 'ES256',
            kid: 'provider-key-id',
            typ: 'oauth-client-attestation+jwt',
            x5c: [cleanCert]
          })
          .sign(providerPrivateKey);
      })()
    : await new SignJWT({
        aal: 'https://trust-list.eu/aal/high',
        sub: clientId,
        cnf: {
          jwk: wallet.walletPublicJwk
        }
      })
        .setProtectedHeader({
          alg: 'ES256',
          jwk: wallet.pureJwk,
          typ: 'oauth-client-attestation+jwt',
          trust_chain: ['test-trust-chain']
        })
        .setIssuer('https://wallet-provider.example')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(wallet.privateKey);

  const attestationPopJwt = await new SignJWT({
    iss: clientId,
    jti: crypto.randomUUID()
  })
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'oauth-client-attestation-pop+jwt'
    })
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(wallet.privateKey);

  return {
    attestationJwt,
    attestationPopJwt
  };
}

async function getLegacyEdocAttestations(wallet: any, audience: string, clientId: string) {
  const attestationJwt = await new SignJWT({
    sub: clientId,
    cnf: {
      jwk: wallet.walletPublicJwk
    }
  })
    .setProtectedHeader({
      alg: 'ES256',
      jwk: wallet.pureJwk,
      typ: 'wallet-attestation+jwt'
    })
    .setIssuer('https://wallet-provider.example')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(wallet.privateKey);

  const attestationPopJwt = await new SignJWT({
    iss: clientId,
    jti: crypto.randomUUID()
  })
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'oauth-client-attestation-pop+jwt'
    })
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(wallet.privateKey);

  return {
    attestationJwt,
    attestationPopJwt
  };
}

async function createRequestObject(wallet: any, authFlow: 'direct' | 'l2plus' | 'l3', baseUrl: string) {
  const payload = {
    client_id: wallet.clientId,
    response_type: 'code',
    response_mode: 'query',
    redirect_uri: REDIRECT_URI,
    state: STATE,

    code_challenge: CODE_CHALLENGE,
    code_challenge_method: 'S256',

    authorization_details: [
      {
        credential_configuration_id: 'dc_sd_jwt_PersonIdentificationData',
        type: 'openid_credential'
      }
    ],

    pid_auth_flow: authFlow,

    jti: crypto.randomUUID()
  };

  return new SignJWT(payload)
    .setProtectedHeader({
      alg: 'ES256',
      kid: wallet.walletPublicJwk.kid,
      typ: 'oauth-authz-req+jwt'
    })
    .setIssuer(wallet.clientId)
    .setAudience(baseUrl)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(wallet.privateKey);
}

async function createDPoP(htu: string, htm: string, wallet: any, accessToken?: string) {
  const payload: any = {
    htm,
    htu,
    jti: crypto.randomUUID()
  };

  if (accessToken) {
    payload.ath = crypto.createHash('sha256').update(accessToken).digest('base64url');
  }

  return new SignJWT(payload)
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: wallet.pureJwk
    })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(wallet.privateKey);
}

async function createCredentialProof(audience: string, nonce: string, wallet: any, keyAttestation?: string) {
  const header: any = {
    alg: 'ES256',
    typ: 'openid4vci-proof+jwt',
    jwk: wallet.pureJwk
  };

  if (keyAttestation) {
    header.key_attestation = keyAttestation;
  }

  return new SignJWT({
    aud: audience,
    nonce,
    iss: wallet.clientId,
    jti: crypto.randomUUID()
  })
    .setProtectedHeader(header)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(wallet.privateKey);
}

async function getAuthorizationCode(
  app: FastifyInstance,
  host: string,
  authFlow: 'direct' | 'l2plus' | 'l3',
  wallet: any,
  clientId: string,
  baseUrl: string,
  attestationJwt: string,
  attestationPopJwt: string,
  requestJwt: string,
  specVersionHeader: Record<string, string | undefined>
): Promise<string> {
  const parResponse = await app.inject({
    method: 'POST',
    url: `${baseUrl}/as/par`,
    headers: {
      host,
      'content-type': 'application/x-www-form-urlencoded',
      'oauth-client-attestation': attestationJwt,
      'oauth-client-attestation-pop': attestationPopJwt,
      ...specVersionHeader
    },
    payload: new URLSearchParams({
      client_id: clientId,
      request: requestJwt
    }).toString()
  });

  expect(parResponse.statusCode).toBe(201);

  const requestUri = parResponse.json().request_uri as string;

  const authorizeResponse = await app.inject({
    method: 'GET',
    url: `${baseUrl}/authorize?client_id=${clientId}&request_uri=${encodeURIComponent(requestUri)}`,
    headers: {
      host,
      ...specVersionHeader
    }
  });

  expect(authorizeResponse.statusCode).toBe(302);

  const authorizeLocation = new URL(authorizeResponse.headers.location as string);

  if (authFlow === 'direct') {
    return authorizeLocation.searchParams.get('code') as string;
  }

  const idpResponse = await app.inject({
    method: 'GET',
    url: authorizeLocation.pathname + authorizeLocation.search,
    headers: {
      host,
      ...specVersionHeader
    }
  });

  expect(idpResponse.statusCode).toBe(302);

  if (authFlow === 'l3') {
    const walletLocation = new URL(idpResponse.headers.location as string);
    return walletLocation.searchParams.get('code') as string;
  }

  const walletLocation = new URL(idpResponse.headers.location as string);
  const challengeInfo = walletLocation.searchParams.get('challenge_info');
  if (!challengeInfo) {
    throw new Error('Missing challenge_info in MRTD flow redirect');
  }

  const challengePayload = decodeJwt(challengeInfo) as Record<string, unknown>;
  const mrtdAuthSession = challengePayload['mrtd_auth_session'] as string;
  const mrtdPopJwtNonce = challengePayload['mrtd_pop_jwt_nonce'] as string;

  const { attestationJwt: edocAttestationJwt, attestationPopJwt: edocAttestationPopJwt } =
    await getLegacyEdocAttestations(wallet, baseUrl, clientId);

  const initResponse = await app.inject({
    method: 'POST',
    url: '/edoc-proof/init',
    headers: {
      host,
      'content-type': 'application/json',
      'oauth-client-attestation': edocAttestationJwt,
      'oauth-client-attestation-pop': edocAttestationPopJwt
    },
    payload: JSON.stringify({ mrtd_auth_session: mrtdAuthSession, mrtd_pop_jwt_nonce: mrtdPopJwtNonce })
  });

  expect(initResponse.statusCode).toBe(202);

  const popPayload = decodeJwt(initResponse.body) as Record<string, unknown>;
  const mrtdPopNonce = popPayload['mrtd_pop_nonce'] as string;

  const fakeB64 = Buffer.from('fake').toString('base64');
  const validationJwt = await new SignJWT({
    aud: baseUrl,
    document_type: 'cie',
    ias: { challenge_signed: fakeB64, ias_pk: fakeB64, sod_ias: fakeB64 },
    iss: clientId,
    mrtd: { dg1: fakeB64, dg11: fakeB64, sod_mrtd: fakeB64 }
  })
    .setProtectedHeader({ alg: 'ES256', kid: wallet.walletPublicJwk.kid, typ: 'mrtd-ias+jwt' })
    .setIssuedAt()
    .setExpirationTime('10m')
    .sign(wallet.privateKey);

  const verifyResponse = await app.inject({
    method: 'POST',
    url: '/edoc-proof/verify',
    headers: {
      host,
      'content-type': 'application/json',
      'oauth-client-attestation': edocAttestationJwt,
      'oauth-client-attestation-pop': edocAttestationPopJwt
    },
    payload: JSON.stringify({
      mrtd_auth_session: mrtdAuthSession,
      mrtd_pop_nonce: mrtdPopNonce,
      mrtd_validation_jwt: validationJwt
    })
  });

  expect(verifyResponse.statusCode).toBe(202);

  const verifyBody = verifyResponse.json() as Record<string, unknown>;
  const mrtdValPopNonce = verifyBody['mrtd_val_pop_nonce'] as string;

  const valPopNonceJwt = await new SignJWT({ nonce: mrtdValPopNonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'mrtd-val-pop+jwt' })
    .setAudience(baseUrl)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(wallet.privateKey);

  const callbackResponse = await app.inject({
    method: 'GET',
    url: `/idp/callback?mrtd_auth_session=${mrtdAuthSession}&mrtd_val_pop_nonce=${encodeURIComponent(valPopNonceJwt)}`,
    headers: {
      host,
      ...specVersionHeader
    }
  });

  expect(callbackResponse.statusCode).toBe(302);

  const callbackLocation = new URL(callbackResponse.headers.location as string);
  return callbackLocation.searchParams.get('code') as string;
}
function decodeSdJwt(sdJwt: string): Record<string, any> {
  const parts = sdJwt.split('~');
  const jwtPayload = decodeJwt(parts[0]);

  const payload = { ...jwtPayload } as Record<string, any>;

  for (let i = 1; i < parts.length - 1; i++) {
    const disclosureBase64 = parts[i];
    if (!disclosureBase64) continue;
    try {
      const disclosureStr = Buffer.from(disclosureBase64, 'base64url').toString('utf8');
      const disclosure = JSON.parse(disclosureStr);
      if (Array.isArray(disclosure) && disclosure.length === 3) {
        const [, key, value] = disclosure;
        payload[key] = value;
      }
    } catch {
      // ignore parsing errors for non-disclosure parts
    }
  }

  return payload;
}

describe('E2E PID Issuance Flows (MRTD)', () => {
  let app: FastifyInstance;

  let BASE_URL: string;

  let HOST: string;

  afterEach(async () => {
    if (app) {
      await app.close();
    }

    for (const key of ENV_KEYS) {
      delete process.env[key];
    }
  });

  const setupEnvironment = async (authFlow: 'direct' | 'l2plus' | 'l3') => {
    app = await createApp(authFlow);

    BASE_URL = getAppBaseUrl();

    HOST = '127.0.0.1:3000';
  };

  async function issueCredential(authFlow: 'direct' | 'l2plus' | 'l3') {
    await setupEnvironment(authFlow);

    const wallet = await buildWallet();
    const clientId = wallet.clientId;

    const isV13 = authFlow === 'l3' || authFlow === 'l2plus';
    const { attestationJwt, attestationPopJwt } = await getAttestations(wallet, BASE_URL, clientId, isV13);

    const requestJwt = await createRequestObject(wallet, authFlow, BASE_URL);

    const specVersionHeader = isV13 ? { 'x-spec-version': '1.3' } : {};

    const authorizationCode = await getAuthorizationCode(
      app,
      HOST,
      authFlow,
      wallet,
      clientId,
      BASE_URL,
      attestationJwt,
      attestationPopJwt,
      requestJwt,
      specVersionHeader
    );

    const tokenResponse = await app.inject({
      method: 'POST',
      url: `${BASE_URL}/token`,
      headers: {
        host: HOST,
        'content-type': 'text/plain',
        'oauth-client-attestation': attestationJwt,
        'oauth-client-attestation-pop': attestationPopJwt,
        dpop: await createDPoP(`${BASE_URL}/token`, 'POST', wallet),
        ...specVersionHeader
      },
      payload: new URLSearchParams({
        code: authorizationCode,
        code_verifier: CODE_VERIFIER,
        grant_type: 'authorization_code',
        redirect_uri: REDIRECT_URI
      }).toString()
    });

    expect(tokenResponse.statusCode).toBe(200);
    const { access_token } = tokenResponse.json() as { access_token: string };

    /**
     * NONCE
     */
    const nonceResponse = await app.inject({
      method: 'POST',

      url: `${BASE_URL}/nonce`,

      headers: {
        host: HOST,
        ...specVersionHeader
      }
    });

    expect(nonceResponse.statusCode).toBe(200);

    const { c_nonce } = nonceResponse.json();

    /**
     * DPoP
     */
    const credentialEndpoint = `${BASE_URL}/credential`;

    const dpopJwt = await createDPoP(credentialEndpoint, 'POST', wallet, access_token);

    let keyAttestationJwt: string | undefined;
    if (isV13) {
      const providerMaterial = await generateIaca();
      const cleanCert = providerMaterial.certPem
        .replace(/-----\s*BEGIN CERTIFICATE\s*-----/, '')
        .replace(/-----\s*END CERTIFICATE\s*-----/, '')
        .replace(/\s/g, '');
      const providerPrivateKey = await importPKCS8(providerMaterial.keyPem, 'ES256');

      keyAttestationJwt = await new SignJWT({
        attested_keys: [wallet.walletPublicJwk],
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: 'https://wallet-provider.example',
        key_storage: ['iso_18045_high'],
        status: {
          status_list: {
            idx: 0,
            uri: 'https://wallet-provider.example/statuslist'
          }
        },
        user_authentication: ['iso_18045_high']
      })
        .setProtectedHeader({
          alg: 'ES256',
          typ: 'key-attestation+jwt',
          kid: 'provider-key-id',
          x5c: [cleanCert]
        })
        .sign(providerPrivateKey);
    }

    /**
     * Credential Proof
     */
    const proofJwt = await createCredentialProof(BASE_URL, c_nonce, wallet, keyAttestationJwt);

    /**
     * Credential Issuance
     */
    const payload = isV13
      ? {
          format: 'vc+sd-jwt',
          credential_identifier: 'dc_sd_jwt_PersonIdentificationData',
          proofs: {
            jwt: [proofJwt]
          }
        }
      : {
          format: 'vc+sd-jwt',
          credential_identifier: 'dc_sd_jwt_PersonIdentificationData',
          proof: {
            proof_type: 'jwt',
            jwt: proofJwt
          }
        };

    const credResponse = await app.inject({
      method: 'POST',

      url: `${BASE_URL}/credential`,

      headers: {
        host: HOST,

        'content-type': 'application/json',

        authorization: `DPoP ${access_token}`,

        dpop: dpopJwt,

        ...specVersionHeader
      },

      payload
    });

    if (credResponse.statusCode !== 200) {
      console.error('[CREDENTIAL ERROR]', credResponse.statusCode, credResponse.body);

      throw new Error(`[Credential Error]: ${credResponse.body}`);
    }

    return credResponse;
  }

  it('1. Legacy Direct Flow (PAR -> nonce -> credential with mock access token)', async () => {
    const credResponse = await issueCredential('direct');

    expect(credResponse.statusCode).toBe(200);
  });

  it('2. L3 Flow (High Assurance) - Inject Fixture Mario Rossi', async () => {
    const credResponse = await issueCredential('l3');

    expect(credResponse.statusCode).toBe(200);

    const body = credResponse.json();

    const jwtString = body.credentials ? body.credentials[0].credential : body.credential;

    const credentialPayload = decodeSdJwt(jwtString) as Record<string, any>;

    expect(credentialPayload.verification.assurance_level).toBe('high');

    expect(credentialPayload.verification.trust_framework).toBe('it_cie');

    expect(credentialPayload.personal_administrative_number).toBe('RSSMRA90T12H501U');

    expect(credentialPayload.family_name).toBe('Rossi');
  });

  it('3. L2+ Flow (Substantial Assurance + Edoc Proof)', async () => {
    const credResponse = await issueCredential('l2plus');

    expect(credResponse.statusCode).toBe(200);

    const body = credResponse.json();

    const jwtString = body.credentials ? body.credentials[0].credential : body.credential;

    const credentialPayload = decodeSdJwt(jwtString) as Record<string, any>;

    expect(credentialPayload.verification.assurance_level).toBe('substantial');

    expect(credentialPayload.verification.trust_framework).toBe('it_l2+document_proof');

    expect(credentialPayload.personal_administrative_number).toBe('RSSMRA90T12H501U');

    expect(credentialPayload.family_name).toBe('Rossi');
  });

  it.skip('4. Regressione EAA - should issue EAA successfully without changes', async () => {
    // TODO: implement an actual EAA issuance regression check in this suite if needed,
    // or rely on the pre-existing specialized EAA route/test files.
  });
});
