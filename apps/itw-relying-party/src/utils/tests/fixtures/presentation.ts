import { generateKeyPairSync } from 'node:crypto';

import { convertPemToBase64Der, createSelfSignedCertificateFromJwk } from '@itw-conformance-tool/crypto';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';

import type { JWK } from 'jose';

/**
 * Shared fixtures for the presentation-verification tests: a real SD-JWT VC,
 * selectively disclosed and bound with a real key binding JWT, exactly as a
 * wallet produces one. Nothing here is stubbed, so a test that passes proves
 * the Verifier accepts a genuine presentation.
 */

export const CREDENTIAL_ID = 'pid';
export const PRESENTATION_NONCE = 'a-nonce-with-enough-entropy';

export const DCQL_QUERY = {
  credentials: [
    {
      claims: [{ path: ['given_name'] }, { path: ['family_name'] }],
      format: 'dc+sd-jwt',
      id: CREDENTIAL_ID,
      meta: { vct_values: ['urn:eudi:pid:it:1'] }
    }
  ]
};

export const DISCLOSED_CLAIMS = { family_name: 'Rossi', given_name: 'Mario' };

export function generateEcJwk(extra: Record<string, unknown>): JWK & { kid: string } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { ...(privateKey.export({ format: 'jwk' }) as JWK), ...extra } as JWK & { kid: string };
}

export function toPublicJwk<T extends JWK>(jwk: T): T {
  const { d: _d, ...publicJwk } = jwk;
  void _d;
  return publicJwk as T;
}

export async function createCertificateBase64Der(jwk: JWK): Promise<string> {
  return convertPemToBase64Der(await createSelfSignedCertificateFromJwk(jwk));
}

export interface CreatePresentationOptions {
  /** Key binding `aud`. */
  audience: string;
  /** Key binding `nonce`; defaults to the request nonce. */
  nonce?: string;
}

/**
 * Issues a PID signed by a throwaway issuer whose certificate travels in the
 * `x5c` header — the key source `VpTokenVerifier` resolves — and presents it
 * with a key binding JWT.
 */
export async function createSdJwtPresentation(options: CreatePresentationOptions): Promise<string> {
  const issuerJwk = generateEcJwk({ alg: 'ES256', kid: 'issuer-key', use: 'sig' });
  const holderJwk = generateEcJwk({ alg: 'ES256', kid: 'holder-key', use: 'sig' });
  const issuerCertificate = await createCertificateBase64Der(issuerJwk);

  const sdJwtVc = new SDJwtVcInstance({
    hashAlg: 'sha-256',
    hasher: digest,
    kbSignAlg: ES256.alg,
    kbSigner: await ES256.getSigner(holderJwk),
    saltGenerator: generateSalt,
    signAlg: ES256.alg,
    signer: await ES256.getSigner(issuerJwk)
  });

  const credential = await sdJwtVc.issue(
    {
      cnf: { jwk: toPublicJwk(holderJwk) },
      iat: Math.floor(Date.now() / 1000),
      iss: 'https://issuer.example.org',
      vct: 'urn:eudi:pid:it:1',
      ...DISCLOSED_CLAIMS
    },
    { _sd: ['given_name', 'family_name'] },
    { header: { alg: 'ES256', kid: issuerJwk.kid, typ: 'dc+sd-jwt', x5c: [issuerCertificate] } }
  );

  return sdJwtVc.present(
    credential,
    { family_name: true, given_name: true },
    {
      kb: {
        payload: {
          aud: options.audience,
          iat: Math.floor(Date.now() / 1000),
          nonce: options.nonce ?? PRESENTATION_NONCE
        }
      }
    }
  );
}
