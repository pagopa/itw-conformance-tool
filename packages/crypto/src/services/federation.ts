import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';

import { validateJWKS } from './validate.js';

export type JwkLike = {
  [key: string]: unknown;
  kty?: string;
  kid?: string;
  key_ops?: string[];
  use?: string;
};

export type JwksLike = {
  keys: JwkLike[];
};

export type SignedJwksValidationResult = {
  uriResolvable: boolean;
  contentTypeValid: boolean;
  compactJwt: boolean;
  payloadHasJwks: boolean;
  signatureValid: boolean;
};

export const ALLOWED_FEDERATION_JOSE_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'] as const;

const PRIVATE_JWK_PARAMS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);

export function hasCompactJwtShape(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

export function hasNoPrivateJwkParams(key: JwkLike): boolean {
  return Object.keys(key).every((prop) => !PRIVATE_JWK_PARAMS.has(prop));
}

export function isPublicSigningJwk(key: JwkLike): boolean {
  const useAllowsSigning = key.use === undefined || key.use === 'sig';
  const keyOpsAllowsSigning =
    key.key_ops === undefined ||
    (Array.isArray(key.key_ops) &&
      key.key_ops.length > 0 &&
      key.key_ops.every((op) => op === 'sign' || op === 'verify'));

  return useAllowsSigning && keyOpsAllowsSigning && hasNoPrivateJwkParams(key);
}

export function isKeySemanticallyConsistent(key: JwkLike): boolean {
  if (!Array.isArray(key.key_ops)) {
    return key.use === undefined || key.use === 'sig' || key.use === 'enc';
  }

  if (key.use === 'sig') {
    return key.key_ops.every((op: string) => op === 'sign' || op === 'verify');
  }

  if (key.use === 'enc') {
    return key.key_ops.every((op: string) =>
      ['encrypt', 'decrypt', 'deriveKey', 'deriveBits', 'wrapKey', 'unwrapKey'].includes(op)
    );
  }

  if (key.use === undefined) {
    return key.key_ops.every((op: string) =>
      ['sign', 'verify', 'encrypt', 'decrypt', 'deriveKey', 'deriveBits', 'wrapKey', 'unwrapKey'].includes(op)
    );
  }

  return false;
}

export async function verifyEntityStatementWithFederationJwks(
  entityStatementJwt: string,
  federationJwks: JwksLike,
  algorithms: readonly string[] = ALLOWED_FEDERATION_JOSE_ALGORITHMS
): Promise<boolean> {
  try {
    await jwtVerify(entityStatementJwt, createLocalJWKSet(federationJwks), {
      algorithms: [...algorithms]
    });
    return true;
  } catch {
    return false;
  }
}

export async function isValidPublicJwks(jwks: unknown): Promise<boolean> {
  try {
    await validateJWKS(jwks);
    const keys = (jwks as { keys?: JwkLike[] })?.keys;
    return Array.isArray(keys) && keys.every((key) => hasNoPrivateJwkParams(key));
  } catch {
    return false;
  }
}

export async function fetchSignedJwksFromUri(
  signedJwksUri: string,
  federationJwks: JwksLike,
  timeoutMs = 5_000
): Promise<JwkLike[]> {
  try {
    const response = await fetch(signedJwksUri, { signal: AbortSignal.timeout(timeoutMs) });
    const contentType = response.headers.get('content-type') ?? '';
    if (response.status !== 200 || !contentType.includes('application/jwk-set+jwt')) {
      return [];
    }

    const signedJwt = await response.text();
    if (!hasCompactJwtShape(signedJwt)) {
      return [];
    }

    decodeProtectedHeader(signedJwt);
    const decoded = decodeJwt(signedJwt) as { jwks?: { keys?: JwkLike[] } };
    const signatureValid = await verifyEntityStatementWithFederationJwks(signedJwt, federationJwks);

    if (!signatureValid) {
      return [];
    }

    return Array.isArray(decoded.jwks?.keys) ? decoded.jwks.keys : [];
  } catch {
    return [];
  }
}

export async function validateSignedJwksUri(
  signedJwksUri: string,
  federationJwks: JwksLike,
  timeoutMs = 5_000
): Promise<SignedJwksValidationResult> {
  const result: SignedJwksValidationResult = {
    uriResolvable: false,
    contentTypeValid: false,
    compactJwt: false,
    payloadHasJwks: false,
    signatureValid: false
  };

  try {
    const response = await fetch(signedJwksUri, { signal: AbortSignal.timeout(timeoutMs) });
    result.uriResolvable = response.status === 200;
    result.contentTypeValid = (response.headers.get('content-type') ?? '').includes('application/jwk-set+jwt');

    if (!result.uriResolvable || !result.contentTypeValid) {
      return result;
    }

    const jwtContent = await response.text();
    result.compactJwt = hasCompactJwtShape(jwtContent);
    if (!result.compactJwt) {
      return result;
    }

    decodeProtectedHeader(jwtContent);
    const signedPayload = decodeJwt(jwtContent) as { jwks?: { keys?: unknown[] } };
    const signedJwksKeys = signedPayload.jwks?.keys;

    result.payloadHasJwks = Array.isArray(signedJwksKeys) && signedJwksKeys.length > 0;
    if (!result.payloadHasJwks) {
      return result;
    }

    result.signatureValid = await verifyEntityStatementWithFederationJwks(jwtContent, federationJwks);
    return result;
  } catch {
    return result;
  }
}
