import { createHash } from 'node:crypto';

import {
  SignJWT,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  type JWK,
  type KeyLike
} from 'jose';

const PII_CLAIMS = new Set([
  'given_name',
  'family_name',
  'email',
  'phone_number',
  'birthdate',
  'address',
  'fiscal_code',
  'tax_id',
  'national_id',
  'personal_id'
]);

export async function createEphemeralWalletKeyPair(): Promise<{ privateKey: KeyLike; publicJwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const publicJwk = { ...(await exportJWK(publicKey)), alg: 'ES256' };
  publicJwk.kid = await calculateJwkThumbprint(publicJwk);
  return { privateKey, publicJwk };
}

export async function buildWiaRequestJwt(input: {
  baseUrl: string;
  nonce: string;
  ephemeralPrivateKey: KeyLike;
  ephemeralPublicJwk: JWK;
  integrityAssertion?: string;
  hardwareSignature?: string;
  platform?: string;
}): Promise<string> {
  const iss = `${input.baseUrl}/instance/${input.ephemeralPublicJwk.kid}`;
  return new SignJWT({
    cnf: { jwk: input.ephemeralPublicJwk },
    hardware_key_tag: 'test-hardware-key-tag',
    hardware_signature: input.hardwareSignature ?? createHash('sha256').update('client-data-hash').digest('base64url'),
    integrity_assertion: input.integrityAssertion ?? 'test-integrity-assertion',
    nonce: input.nonce,
    platform: input.platform ?? 'test',
    wallet_solution_id: 'itw-conformance-wallet',
    wallet_solution_version: '1.0.0'
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid: input.ephemeralPublicJwk.kid,
      typ: 'wia-request+jwt'
    })
    .setIssuer(iss)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(input.ephemeralPrivateKey);
}

export function containsPiiClaim(value: unknown, path = ''): string[] {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => containsPiiClaim(item, `${path}[${index}]`));
  }
  if (typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, nested]) => {
      const currentPath = path ? `${path}.${key}` : key;
      if (PII_CLAIMS.has(key)) return [currentPath];
      return containsPiiClaim(nested, currentPath);
    });
  }
  return [];
}

export async function verifyWalletAttestationSignature(
  walletAttestationJwt: string,
  federationPublicJwk: JWK
): Promise<boolean> {
  try {
    await jwtVerify(walletAttestationJwt, await importJWK(federationPublicJwk, 'ES256'));
    return true;
  } catch {
    return false;
  }
}

export type ConformanceDebugSnapshot = {
  federation_access_log: Array<{ method: string; path: string; timestamp: string }>;
  attestation_issuance_log: Array<{ ephemeralKeyThumbprint: string; timestamp: string }>;
  revocation_notifications: Array<{ instanceId: string; revokedAt: string; notifiedAt: string }>;
};
