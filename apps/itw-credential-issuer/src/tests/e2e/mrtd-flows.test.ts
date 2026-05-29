import crypto from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import fp from 'fastify-plugin';
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, importPKCS8, SignJWT } from 'jose';
import { afterEach, describe, expect, it } from 'vitest';

import bootstrap from '../../app.js';
import { generateIaca, generateJwks } from '../../crypto/auto-keygen.js';

import type { FastifyInstance } from 'fastify';

const CLIENT_ID = '123e4567-e89b-12d3-a456-426614174000';

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

  await app.register(fp(bootstrap));

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

async function getAttestations(wallet: any, audience: string) {
  const attestationJwt = await new SignJWT({
    sub: CLIENT_ID,
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
    iss: CLIENT_ID,
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
    client_id: CLIENT_ID,
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
      alg: 'ES256'
    })
    .setIssuer(CLIENT_ID)
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
    iss: CLIENT_ID,
    jti: crypto.randomUUID()
  })
    .setProtectedHeader(header)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(wallet.privateKey);
}

/**
 * Generates mock AT signed with runtime issuer keys.
 */
async function generateMockAccessToken(authFlow: string, wallet: any, baseUrl: string) {
  const jwksRaw = readFileSync(path.join(process.env.DATA_DIR!, 'issuer/signing-keys.jwks.json'), 'utf8');

  const jwks = JSON.parse(jwksRaw);

  const serverPrivateKey = await importJWK(jwks.keys[0], 'ES256');

  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({
    iss: baseUrl,
    sub: CLIENT_ID,
    client_id: CLIENT_ID,
    aud: baseUrl,

    cnf: {
      jkt: await calculateJwkThumbprint(wallet.pureJwk, 'sha256')
    },

    auth_flow: authFlow,

    jti: crypto.randomUUID()
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid: jwks.keys[0].kid,
      typ: 'at+jwt'
    })
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(serverPrivateKey);
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

    const { attestationJwt, attestationPopJwt } = await getAttestations(wallet, BASE_URL);

    const requestJwt = await createRequestObject(wallet, authFlow, BASE_URL);

    const isV13 = authFlow === 'l3' || authFlow === 'l2plus';
    const specVersionHeader = isV13 ? { 'x-spec-version': '1.3' } : {};

    /**
     * PAR
     */
    const parResponse = await app.inject({
      method: 'POST',

      url: `${BASE_URL}/as/par`,

      headers: {
        host: HOST,

        'content-type': 'application/x-www-form-urlencoded',

        'oauth-client-attestation': attestationJwt,

        'oauth-client-attestation-pop': attestationPopJwt,

        ...specVersionHeader
      },

      payload: new URLSearchParams({
        client_id: CLIENT_ID,
        request: requestJwt
      }).toString()
    });

    expect(parResponse.statusCode).toBe(201);

    /**
     * Mock Access Token
     */
    const access_token = await generateMockAccessToken(authFlow, wallet, BASE_URL);

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
