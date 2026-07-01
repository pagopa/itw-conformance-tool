import { isValidJwk } from '@itw-conformance-tool/crypto';
import { calculateJwkThumbprint, createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

type JwkLike = {
  [key: string]: unknown;
  kty?: string;
  kid?: string;
  key_ops?: string[];
  use?: string;
};

type WalletMetadata = {
  wallet_name?: string;
  credential_offer_endpoint?: string;
  [key: string]: unknown;
};

type WalletSolutionMetadata = {
  jwks?: { keys?: JwkLike[] };
  jwks_uri?: string;
  signed_jwks_uri?: string;
  logo_uri?: string;
  wallet_metadata?: WalletMetadata;
  [key: string]: unknown;
};

type EntityMetadata = {
  wallet_solution?: WalletSolutionMetadata;
  federation_entity?: Record<string, unknown>;
};

type EntityPayload = {
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  authority_hints: string[];
  jwks?: { keys: JwkLike[] };
  metadata: EntityMetadata;
  [key: string]: unknown;
};

const ALLOWED_JOSE_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'] as const;

const PRIVATE_JWK_PARAMS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);

function hasCompactJwtShape(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

function hasNoPrivateJwkParams(key: JwkLike): boolean {
  return Object.keys(key).every((prop) => !PRIVATE_JWK_PARAMS.has(prop));
}

function isPublicSigningJwk(key: JwkLike): boolean {
  const useAllowsSigning = key.use === undefined || key.use === 'sig';
  const keyOpsAllowsSigning =
    key.key_ops === undefined ||
    (Array.isArray(key.key_ops) &&
      key.key_ops.length > 0 &&
      key.key_ops.every((op) => op === 'sign' || op === 'verify'));

  return useAllowsSigning && keyOpsAllowsSigning && hasNoPrivateJwkParams(key);
}

async function verifyEntityStatementWithFederationJwks(
  entityStatementJwt: string,
  federationJwks: { keys: JwkLike[] }
): Promise<boolean> {
  try {
    await jwtVerify(entityStatementJwt, createLocalJWKSet(federationJwks), {
      algorithms: [...ALLOWED_JOSE_ALGORITHMS]
    });
    return true;
  } catch {
    return false;
  }
}

async function fetchJwksFromUri(jwksUri: string): Promise<JwkLike[]> {
  try {
    const response = await fetch(jwksUri, { signal: AbortSignal.timeout(5_000) });
    const contentType = response.headers.get('content-type') ?? '';
    if (response.status !== 200 || !contentType.includes('application/json')) {
      return [];
    }

    const body = (await response.json()) as { keys?: JwkLike[] };
    return Array.isArray(body.keys) ? body.keys : [];
  } catch {
    return [];
  }
}

async function fetchSignedJwksFromUri(signedJwksUri: string, federationJwks: { keys: JwkLike[] }): Promise<JwkLike[]> {
  try {
    const response = await fetch(signedJwksUri, { signal: AbortSignal.timeout(5_000) });
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

type SignedJwksValidationResult = {
  uriResolvable: boolean;
  contentTypeValid: boolean;
  compactJwt: boolean;
  payloadHasJwks: boolean;
  signatureValid: boolean;
};

async function validateSignedJwksUri(
  signedJwksUri: string,
  federationJwks: { keys: JwkLike[] }
): Promise<SignedJwksValidationResult> {
  const result: SignedJwksValidationResult = {
    uriResolvable: false,
    contentTypeValid: false,
    compactJwt: false,
    payloadHasJwks: false,
    signatureValid: false
  };

  try {
    const response = await fetch(signedJwksUri, { signal: AbortSignal.timeout(5_000) });
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

async function resolveWalletSolutionKeys(
  walletSolution: WalletSolutionMetadata,
  federationJwks: { keys: JwkLike[] }
): Promise<JwkLike[]> {
  if (Array.isArray(walletSolution.jwks?.keys) && walletSolution.jwks.keys.length > 0) {
    return walletSolution.jwks.keys;
  }

  const jwksUri = walletSolution.jwks_uri;
  if (typeof jwksUri === 'string' && isHttpsUrl(jwksUri)) {
    return fetchJwksFromUri(jwksUri);
  }

  const signedJwksUri = walletSolution.signed_jwks_uri;
  if (typeof signedJwksUri === 'string' && isHttpsUrl(signedJwksUri)) {
    return fetchSignedJwksFromUri(signedJwksUri, federationJwks);
  }

  return [];
}

function normalizeUrl(url: string): string {
  let normalized = url;
  while (normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

function isHttpsUrl(value: unknown): boolean {
  if (typeof value !== 'string') return false;

  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

function isKeySemanticallyConsistent(key: JwkLike): boolean {
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

describe.sequential(`Wallet Provider Backend`, () => {
  let walletProviderUrl: string;
  let entityConfigResponse: { statusCode: number; body: string };

  // __ Bones values
  let jwt = {
    header: {} as Record<string, unknown>,
    payload: {} as EntityPayload,
    signature: ''
  };
  let payload = {} as EntityPayload;
  let entityStatementSignatureValid = false;

  beforeAll(async () => {
    const walletProviderBackendUrl = process.env.ITW_CT_WALLET_PROVIDER_BACKEND_URL?.trim();
    if (!walletProviderBackendUrl) {
      throw new Error('Missing required env: ITW_CT_WALLET_PROVIDER_BACKEND_URL');
    }

    walletProviderUrl = normalizeUrl(walletProviderBackendUrl);

    try {
      const rawResponse = await fetch(`${walletProviderUrl}/.well-known/openid-federation`, {
        signal: AbortSignal.timeout(5_000)
      });
      entityConfigResponse = { statusCode: rawResponse.status, body: await rawResponse.text() };
    } catch {
      entityConfigResponse = { statusCode: 0, body: '' };
    }
  });

  // ___ WP_001 ____
  it('WP_001 - Execute a GET request to /.well-known/openid-federation and returns 200', async () => {
    expect(entityConfigResponse.statusCode, `Expected /.well-known/openid-federation to return HTTP 200`).toBe(200);
    expect(
      hasCompactJwtShape(entityConfigResponse.body),
      `Expected entity configuration response to be a compact JWT`
    ).toBe(true);
  });

  // ___ WP_002 ____
  it('WP_002 - Entity configuration is an OpenID Federation-compliant signed JWT with all required components', async () => {
    try {
      const header = decodeProtectedHeader(entityConfigResponse.body) as Record<string, unknown>;
      const decodedPayload = decodeJwt(entityConfigResponse.body) as EntityPayload;
      const signature = entityConfigResponse.body.split('.')[2] ?? '';

      if (!decodedPayload.jwks || !Array.isArray(decodedPayload.jwks.keys) || decodedPayload.jwks.keys.length === 0) {
        throw new Error('Entity configuration payload jwks is missing or empty');
      }

      entityStatementSignatureValid = await verifyEntityStatementWithFederationJwks(
        entityConfigResponse.body,
        decodedPayload.jwks
      );

      jwt = { header, payload: decodedPayload, signature };
      payload = decodedPayload;
    } catch {
      throw new Error('Entity configuration is not a well-formed compact JWT');
    }

    expect(entityStatementSignatureValid, `Entity configuration JWT signature is invalid`).toBe(true);
  });

  it("WP_002a - 'alg' must be allowed and not 'none'", async () => {
    const isValidAlg =
      typeof jwt.header.alg === 'string' &&
      ALLOWED_JOSE_ALGORITHMS.includes(jwt.header.alg as (typeof ALLOWED_JOSE_ALGORITHMS)[number]);

    expect(isValidAlg, `JWT header alg is missing, unsupported, or set to none`).toBe(true);
  });

  it("WP_002b - 'kid' must equal public key thumbprint", async () => {
    const hasJwks = Array.isArray(payload.jwks?.keys) && payload.jwks?.keys.length > 0;
    const foundJwk = payload.jwks?.keys?.find((key: JwkLike) => key.kid === jwt.header.kid);
    const kidMatchesThumbprint = !!foundJwk && (await calculateJwkThumbprint(foundJwk)) === jwt.header.kid;
    const signatureVerifiedWithFederationJwks = hasJwks
      ? await verifyEntityStatementWithFederationJwks(entityConfigResponse.body, payload.jwks as { keys: JwkLike[] })
      : false;

    expect(
      kidMatchesThumbprint && signatureVerifiedWithFederationJwks,
      `JWT header kid must match a JWK thumbprint and verify the JWT signature`
    ).toBe(true);
  });

  it("WP_002c - 'typ' must be 'entity-statement+jwt'", async () => {
    const isValidTyp = jwt.header.typ === 'entity-statement+jwt';

    expect(isValidTyp, `JWT header typ is missing or incorrect`).toBe(true);
  });

  it("WP_002d - 'iss' and 'sub' must be equal and valid HTTPS URLs", async () => {
    const isValidIssuer = typeof payload.iss === 'string' && isHttpsUrl(payload.iss);
    const isValidSubject = typeof payload.sub === 'string' && isHttpsUrl(payload.sub);
    const normalizedIssuer = isValidIssuer ? normalizeUrl(payload.iss) : '';
    const normalizedSubject = isValidSubject ? normalizeUrl(payload.sub) : '';
    const issEqualsSubject = normalizedIssuer.length > 0 && normalizedIssuer === normalizedSubject;
    const matchesWalletProviderUrl = normalizedIssuer === walletProviderUrl && normalizedSubject === walletProviderUrl;

    expect(
      isValidIssuer && isValidSubject && issEqualsSubject && matchesWalletProviderUrl,
      `JWT payload iss and sub must be equal HTTPS URLs and match wallet provider public URL`
    ).toBe(true);
  });

  it("WP_002e - 'iat' and 'exp' must be valid Unix timestamps and not expired", async () => {
    const isValidIat = typeof payload.iat === 'number' && Number.isInteger(payload.iat) && payload.iat > 0;
    const isValidExp = typeof payload.exp === 'number' && Number.isInteger(payload.exp) && payload.exp > payload.iat;
    const isNotExpired = typeof payload.exp === 'number' && payload.exp > Math.floor(Date.now() / 1000);

    expect(
      isValidIat && isValidExp && isNotExpired,
      `JWT payload iat and exp must be valid Unix timestamps and not expired`
    ).toBe(true);
  });

  it("WP_002f - 'authority_hints' must be array of valid HTTPS URLs", async () => {
    const hasAuthorityHints = Array.isArray(payload.authority_hints);
    const allValidAuthorityHints =
      hasAuthorityHints && payload.authority_hints.length > 0 && payload.authority_hints.every(isHttpsUrl);

    expect(
      allValidAuthorityHints,
      `JWT payload authority_hints must be a non-empty array of valid HTTPS URLs; trust-chain validation requires dedicated fixtures`
    ).toBe(true);
  });

  it("WP_002g - 'jwks' must contain valid JWK signing keys", async () => {
    const jwksKeys = payload.jwks?.keys ?? [];
    const hasJwks = Array.isArray(payload.jwks?.keys) && payload.jwks.keys.length > 0;
    const allKeysValid = hasJwks && (await Promise.all(jwksKeys.map(isValidJwk))).every(Boolean);
    const hasPublicSigningKey = jwksKeys.some((key) => isPublicSigningJwk(key));
    const signatureVerified = hasJwks
      ? await verifyEntityStatementWithFederationJwks(entityConfigResponse.body, payload.jwks as { keys: JwkLike[] })
      : false;

    expect(
      allKeysValid && hasPublicSigningKey && signatureVerified,
      `JWT payload jwks must contain valid public signing keys and verify the entity statement signature`
    ).toBe(true);
  });

  it("WP_002h - 'metadata' must contain required wallet_solution and federation_entity fields", async () => {
    const metadataValid = typeof payload.metadata === 'object' && payload.metadata !== null;
    const metadata = metadataValid ? payload.metadata : undefined;
    const walletSolution = metadata?.wallet_solution;
    const walletSolutionValid = typeof walletSolution === 'object' && walletSolution !== null;
    const federationEntityValid =
      metadata?.federation_entity === undefined ||
      (typeof metadata.federation_entity === 'object' && metadata.federation_entity !== null);

    const logoUriValid = isHttpsUrl(walletSolution?.logo_uri);
    const walletMetadataValid =
      typeof walletSolution?.wallet_metadata === 'object' && walletSolution.wallet_metadata !== null;
    const walletNameValid =
      typeof walletSolution?.wallet_metadata?.wallet_name === 'string' &&
      walletSolution.wallet_metadata.wallet_name.trim().length > 0;
    const credentialOfferEndpointValid = isHttpsUrl(walletSolution?.wallet_metadata?.credential_offer_endpoint);

    expect(
      metadataValid &&
        walletSolutionValid &&
        federationEntityValid &&
        logoUriValid &&
        walletMetadataValid &&
        walletNameValid &&
        credentialOfferEndpointValid,
      `JWT payload metadata must contain wallet_solution with logo_uri and wallet_metadata fields; federation_entity is optional but must be an object when present`
    ).toBe(true);
  });

  // ___ WP_003 ____
  it('WP_003 - Public keys are used exclusively for signing/encryption in Wallet Provider role', async () => {
    const decodedPayload = decodeJwt(entityConfigResponse.body) as EntityPayload;
    const walletSolution = decodedPayload.metadata?.wallet_solution;
    const federationJwks = decodedPayload.jwks;
    const hasWalletSolution = typeof walletSolution === 'object' && walletSolution !== null;
    const hasFederationJwks = !!federationJwks && Array.isArray(federationJwks.keys) && federationJwks.keys.length > 0;

    expect(
      hasWalletSolution && hasFederationJwks,
      `Entity configuration must expose metadata.wallet_solution and federation jwks`
    ).toBe(true);

    const candidateKeys =
      hasWalletSolution && hasFederationJwks ? await resolveWalletSolutionKeys(walletSolution, federationJwks) : [];

    expect(
      candidateKeys.length > 0,
      `No wallet_solution keys could be resolved from jwks, jwks_uri, or signed_jwks_uri`
    ).toBe(true);

    const allCandidateKeysValid = (await Promise.all(candidateKeys.map(isValidJwk))).every(Boolean);
    const allKeysPublic = candidateKeys.every((key: JwkLike) => hasNoPrivateJwkParams(key));
    const allKeysForSigningOrEncryption = candidateKeys.every((key: JwkLike) => isKeySemanticallyConsistent(key));

    expect(
      allCandidateKeysValid && allKeysPublic && allKeysForSigningOrEncryption,
      `Wallet Provider keys must be valid public JWKs and restricted to signing/encryption semantics`
    ).toBe(true);
  });

  // ___ WP_004 ____
  it('WP_004 - Public keys are referenced with exactly one of jwks, jwks_uri, or signed_jwks_uri', async () => {
    try {
      payload = decodeJwt(entityConfigResponse.body) as EntityPayload;
    } catch {
      throw new Error('Entity configuration is not a well-formed compact JWT for WP_004 checks');
    }

    expect(
      typeof payload.metadata?.wallet_solution === 'object' && payload.metadata.wallet_solution !== null,
      `metadata.wallet_solution must be present`
    ).toBe(true);
  });

  it('WP_004a - exactly one key reference claim is present and jwks is valid when used', async () => {
    const walletSolution = payload.metadata.wallet_solution;
    const hasJwksRef = walletSolution?.jwks !== undefined;
    const hasJwksUriRef = walletSolution?.jwks_uri !== undefined;
    const hasSignedJwksUriRef = walletSolution?.signed_jwks_uri !== undefined;

    const count = [hasJwksRef, hasJwksUriRef, hasSignedJwksUriRef].filter(Boolean).length;
    const exactlyOne = count === 1;

    const jwksKeys = walletSolution?.jwks?.keys ?? [];
    const allWalletJwksValid =
      !hasJwksRef ||
      (Array.isArray(jwksKeys) &&
        jwksKeys.length > 0 &&
        (await Promise.all(jwksKeys.map(async (key) => (await isValidJwk(key)) && hasNoPrivateJwkParams(key)))).every(
          Boolean
        ));

    const jwksValid =
      !hasJwksRef ||
      (Array.isArray(jwksKeys) &&
        jwksKeys.length > 0 &&
        jwksKeys.every((key: JwkLike) => typeof key.kty === 'string' && typeof key.kid === 'string') &&
        allWalletJwksValid);

    expect(
      exactlyOne && jwksValid,
      `Expected exactly one of metadata.wallet_solution.jwks/jwks_uri/signed_jwks_uri and valid public jwks when present`
    ).toBe(true);
  });

  it('WP_004b - jwks_uri is valid HTTPS and resolvable when present', async () => {
    const walletSolution = payload.metadata.wallet_solution;
    const hasJwksUriRef = walletSolution?.jwks_uri !== undefined;
    if (!hasJwksUriRef) {
      expect(hasJwksUriRef).toBe(false);
      return;
    }

    const jwksUri = walletSolution?.jwks_uri;
    const jwksUriValid = isHttpsUrl(jwksUri);
    let jwksUriResolvable = false;
    let jsonContentType = false;
    let bodyHasJwks = false;
    let allKeysValid = false;

    if (jwksUriValid) {
      try {
        const response = await fetch(jwksUri as string, { signal: AbortSignal.timeout(5_000) });
        jwksUriResolvable = response.status === 200;
        jsonContentType = (response.headers.get('content-type') ?? '').includes('application/json');

        if (jwksUriResolvable && jsonContentType) {
          const decoded = (await response.json()) as { keys?: JwkLike[] };
          const keys = decoded.keys ?? [];
          bodyHasJwks = Array.isArray(keys) && keys.length > 0;
          allKeysValid = bodyHasJwks && (await Promise.all(keys.map(isValidJwk))).every(Boolean);
        }
      } catch {
        jwksUriResolvable = false;
      }
    }

    expect(
      jwksUriValid && jwksUriResolvable && jsonContentType && bodyHasJwks && allKeysValid,
      `metadata.wallet_solution.jwks_uri must be HTTPS, return HTTP 200 JSON, and contain valid JWKS`
    ).toBe(true);
  });

  it('WP_004c - signed_jwks_uri points to valid signed JWKS when present', async () => {
    const walletSolution = payload.metadata.wallet_solution;
    const hasSignedJwksUriRef = walletSolution?.signed_jwks_uri !== undefined;
    if (!hasSignedJwksUriRef) {
      expect(hasSignedJwksUriRef).toBe(false);
      return;
    }

    const signedJwksUri = walletSolution?.signed_jwks_uri;
    const signedJwksUriValid = isHttpsUrl(signedJwksUri);
    const hasFederationJwks = !!payload.jwks && Array.isArray(payload.jwks.keys) && payload.jwks.keys.length > 0;

    const signedValidation =
      signedJwksUriValid && hasFederationJwks
        ? await validateSignedJwksUri(signedJwksUri as string, payload.jwks as { keys: JwkLike[] })
        : {
            uriResolvable: false,
            contentTypeValid: false,
            compactJwt: false,
            payloadHasJwks: false,
            signatureValid: false
          };

    const validSignedJwks =
      signedJwksUriValid &&
      signedValidation.uriResolvable &&
      signedValidation.contentTypeValid &&
      signedValidation.compactJwt &&
      signedValidation.payloadHasJwks &&
      signedValidation.signatureValid;

    expect(
      validSignedJwks,
      `metadata.wallet_solution.signed_jwks_uri must be HTTPS, return HTTP 200 application/jwk-set+jwt, include JWKS payload, and pass signature verification`
    ).toBe(true);
  });

  // ___ WP_008 ____
  it('WP_008 - Wallet Provider supports credential revocation requests from Issuers', async () => {
    // const walletInstanceIds = parseStringArrayEnv('ITW_CT_WP_PDND_WALLET_INSTANCE_IDS');
    // const revocationEndpoint =
    //   readTrimmedEnv('ITW_CT_WP_PDND_WALLET_INSTANCES_ENDPOINT') ?? `${walletProviderUrl}/wallet-instances`;
    // const digest = readTrimmedEnv('ITW_CT_WP_PDND_DIGEST');
    // const agidJwtSignature = readTrimmedEnv('ITW_CT_WP_PDND_AGID_JWT_SIGNATURE');
    // const dpop = readTrimmedEnv('ITW_CT_WP_PDND_DPOP');
    // const authorization = readTrimmedEnv('ITW_CT_WP_PDND_AUTHORIZATION');
    // const extraHeaders = parseHeaderEnv('ITW_CT_WP_PDND_HEADERS_JSON');
    // const headers: HeaderMap = {
    //   'Content-Type': 'application/merge-patch+json',
    //   Digest: digest ?? '',
    //   'Agid-JWT-Signature': agidJwtSignature ?? '',
    //   ...extraHeaders
    // };
    // if (authorization) {
    //   headers.Authorization = authorization;
    // }
    // if (dpop) {
    //   headers.DPoP = dpop;
    // }
    // const revocationResponse = await fetch(revocationEndpoint, {
    //   method: 'PATCH',
    //   body: JSON.stringify({ wallet_instance_ids: walletInstanceIds }),
    //   headers,
    //   signal: AbortSignal.timeout(5_000)
    // });
    // expect(
    //   revocationResponse.status === 200 || revocationResponse.status === 202,
    //   `Wallet Provider does not support credential revocation requests from Issuers`
    // ).toBe(true);
  });

  // ___ WP_010 ____
  it('WP_010 - Wallet instance revocation terminates all instance operations', async () => {
    // const revokedInstanceId = 'revoked-wallet-instance-id';
    // const revokeInstancePayload = {
    //   instance_id: revokedInstanceId,
    //   reason: 'user_request',
    //   iat: Math.floor(Date.now() / 1000)
    // };
    // const revokeResponse = await fetch(`${walletProviderUrl}/revoke-instance`, {
    //   method: 'POST',
    //   body: JSON.stringify(revokeInstancePayload),
    //   headers: { 'Content-Type': 'application/json' },
    //   signal: AbortSignal.timeout(5_000)
    // });
    // const revocationAcknowledged = revokeResponse.status === 200 || revokeResponse.status === 202;
    // const followupPayload = {
    //   instance_id: revokedInstanceId,
    //   operation: 'verify_credential',
    //   data: {}
    // };
    // const followupResponse = await fetch(`${walletProviderUrl}/verify-credential`, {
    //   method: 'POST',
    //   body: JSON.stringify(followupPayload),
    //   headers: { 'Content-Type': 'application/json' },
    //   signal: AbortSignal.timeout(5_000)
    // });
    // const followupOperationBlocked = followupResponse.status === 403 || followupResponse.status === 404;
    // const isValidBehavior = revocationAcknowledged && followupOperationBlocked;
    // const evaluation = await recordRequirement('WP_010', async () => ({
    //   result: isValidBehavior ? 'PASS' : 'FAIL',
    //   httpStatus: revokeResponse.status,
    //   errorMessage: isValidBehavior
    //     ? undefined
    //     : `Wallet instance revocation does not terminate all instance operations`
    // }));
    // if (evaluation === null) {
    //   return;
    // }
    // expect(evaluation.result).toBe('PASS');
  });
});
