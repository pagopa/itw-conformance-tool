import { createHash } from 'node:crypto';

import {
  ALLOWED_FEDERATION_JOSE_ALGORITHMS,
  fetchSignedJwksFromUri,
  hasCompactJwtShape,
  hasNoPrivateJwkParams,
  isKeySemanticallyConsistent,
  isPublicSigningJwk,
  isValidJwk,
  isValidPublicJwks,
  validateSignedJwksUri,
  verifyEntityStatementWithFederationJwks
} from '@itw-conformance-tool/crypto';
import { calculateJwkThumbprint, decodeJwt, decodeProtectedHeader } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { isHttpsUrl, normalizeUrl } from '../../utils/url.js';

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

type HeaderMap = Record<string, string>;

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

function buildSha256DigestHeader(body: string): string {
  const digestHex = createHash('sha256').update(body).digest('hex');
  return `SHA-256=${digestHex}`;
}

const httpsUrlSchema = z.string().refine((value) => isHttpsUrl(value));
const optionalHttpsUrlSchema = httpsUrlSchema.optional();
const nonEmptyStringSchema = z.string().trim().min(1);

const walletJwksSchema = z
  .object({
    keys: z.array(z.custom<JwkLike>((value) => typeof value === 'object' && value !== null)).min(1)
  })
  .superRefine(async (value, ctx) => {
    const jwksValid = await isValidPublicJwks(value);
    if (!jwksValid) {
      ctx.addIssue({
        code: 'custom',
        message: 'Invalid public JWKS in wallet_solution.jwks'
      });
    }
  });

const walletMetadataSchema = z
  .object({
    wallet_name: nonEmptyStringSchema,
    credential_offer_endpoint: httpsUrlSchema
  })
  .catchall(z.unknown());

const walletSolutionMetadataSchema = z
  .object({
    jwks: walletJwksSchema.optional(),
    jwks_uri: optionalHttpsUrlSchema,
    signed_jwks_uri: optionalHttpsUrlSchema,
    logo_uri: httpsUrlSchema,
    wallet_metadata: walletMetadataSchema
  })
  .catchall(z.unknown())
  .superRefine((value, ctx) => {
    const keyRefCount = [value.jwks, value.jwks_uri, value.signed_jwks_uri].filter(
      (entry) => entry !== undefined
    ).length;
    if (keyRefCount !== 1) {
      ctx.addIssue({
        code: 'custom',
        message: 'Exactly one of jwks, jwks_uri, or signed_jwks_uri must be present'
      });
    }
  });

const federationEntityMetadataSchema = z
  .object({
    organization_name: nonEmptyStringSchema.optional(),
    homepage_uri: optionalHttpsUrlSchema,
    policy_uri: optionalHttpsUrlSchema,
    logo_uri: optionalHttpsUrlSchema,
    contacts: z.array(nonEmptyStringSchema).min(1).optional(),
    tos_uri: optionalHttpsUrlSchema,
    federation_resolve_endpoint: optionalHttpsUrlSchema,
    federation_fetch_endpoint: optionalHttpsUrlSchema,
    federation_list_endpoint: optionalHttpsUrlSchema,
    federation_trust_mark_status_endpoint: optionalHttpsUrlSchema,
    federation_trust_mark_list_endpoint: optionalHttpsUrlSchema,
    federation_subordinate_events_endpoint: optionalHttpsUrlSchema
  })
  .catchall(z.unknown());

type PdndRevocationResult = {
  revoked: string[];
  not_found: string[];
  already_revoked: string[];
};

let lastPdndRevocationResult: PdndRevocationResult | null = null;

async function isValidWalletSolutionMetadataSchema(walletSolution: WalletSolutionMetadata): Promise<boolean> {
  const parsed = await walletSolutionMetadataSchema.safeParseAsync(walletSolution);
  return parsed.success;
}

function isValidFederationEntityMetadataSchema(federationEntity: unknown): boolean {
  return federationEntityMetadataSchema.safeParse(federationEntity).success;
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
      ALLOWED_FEDERATION_JOSE_ALGORITHMS.includes(
        jwt.header.alg as (typeof ALLOWED_FEDERATION_JOSE_ALGORITHMS)[number]
      );

    expect(isValidAlg, `JWT header alg is missing, unsupported, or set to none`).toBe(true);
  });

  it("WP_002b - 'kid' must equal public key thumbprint", async () => {
    const hasJwks = Array.isArray(payload.jwks?.keys) && payload.jwks?.keys.length > 0;
    const foundJwk = payload.jwks?.keys?.find((key: JwkLike) => key.kid === jwt.header.kid);
    const kidMatchesThumbprint = !!foundJwk && (await calculateJwkThumbprint(foundJwk)) === jwt.header.kid;
    const signatureVerifiedWithFederationJwks =
      hasJwks && payload.jwks
        ? await verifyEntityStatementWithFederationJwks(entityConfigResponse.body, payload.jwks)
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
    const jwksStructurallyValid = hasJwks ? await isValidPublicJwks(payload.jwks) : false;
    const hasPublicSigningKey = jwksKeys.some((key) => isPublicSigningJwk(key));
    const signatureVerified =
      hasJwks && payload.jwks
        ? await verifyEntityStatementWithFederationJwks(entityConfigResponse.body, payload.jwks)
        : false;

    expect(
      jwksStructurallyValid && hasPublicSigningKey && signatureVerified,
      `JWT payload jwks must contain valid public signing keys and verify the entity statement signature`
    ).toBe(true);
  });

  it("WP_002h - 'metadata' must contain required wallet_solution and federation_entity fields", async () => {
    const metadataValid = typeof payload.metadata === 'object' && payload.metadata !== null;
    const metadata = metadataValid ? payload.metadata : undefined;
    const walletSolution = metadata?.wallet_solution;
    const walletSolutionValid = typeof walletSolution === 'object' && walletSolution !== null;
    const walletSolutionSchemaValid = walletSolutionValid
      ? await isValidWalletSolutionMetadataSchema(walletSolution)
      : false;

    const federationEntityPresent = metadata?.federation_entity !== undefined;
    const federationEntitySchemaValid =
      !federationEntityPresent || isValidFederationEntityMetadataSchema(metadata?.federation_entity);

    expect(
      metadataValid && walletSolutionValid && walletSolutionSchemaValid && federationEntitySchemaValid,
      `JWT payload metadata must contain wallet_solution and may include federation_entity; when federation_entity is present it must respect its schema types`
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

    const jwksValid = !hasJwksRef || (await isValidPublicJwks(walletSolution?.jwks));

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
          allKeysValid = bodyHasJwks && (await isValidPublicJwks(decoded));
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
    const signedJwksUriString = typeof signedJwksUri === 'string' ? signedJwksUri : '';
    const signedJwksUriValid = isHttpsUrl(signedJwksUri);
    const hasFederationJwks = !!payload.jwks && Array.isArray(payload.jwks.keys) && payload.jwks.keys.length > 0;

    const signedValidation =
      signedJwksUriValid && hasFederationJwks && payload.jwks
        ? await validateSignedJwksUri(signedJwksUriString, payload.jwks)
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
    const walletInstanceIds = ['itw-conformance-test-wallet-instance-id'];
    const revocationEndpoint = `${walletProviderUrl}/wallet-instances`;
    const body = JSON.stringify({ wallet_instance_ids: walletInstanceIds });
    const digest = buildSha256DigestHeader(body);
    const headers: HeaderMap = {
      'Content-Type': 'application/merge-patch+json',
      Digest: digest,
      'Agid-JWT-Signature': 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.dGVzdA.dGVzdA'
    };

    let revocationResponseStatus = 0;
    let responseContentType = '';
    let responseBodyHasResultShape = false;

    try {
      const revocationResponse = await fetch(revocationEndpoint, {
        method: 'PATCH',
        body,
        headers,
        signal: AbortSignal.timeout(10_000)
      });

      revocationResponseStatus = revocationResponse.status;
      responseContentType = revocationResponse.headers.get('content-type') ?? '';

      const responseText = await revocationResponse.text();
      if (responseText.length > 0 && responseContentType.includes('application/json')) {
        try {
          const parsed = JSON.parse(responseText) as Record<string, unknown>;
          const result = parsed.result as Record<string, unknown> | undefined;
          const hasExpectedResultShape =
            typeof parsed.result_description === 'string' &&
            !!result &&
            Array.isArray(result.revoked) &&
            Array.isArray(result.not_found) &&
            Array.isArray(result.already_revoked);

          responseBodyHasResultShape = hasExpectedResultShape;
          if (hasExpectedResultShape) {
            lastPdndRevocationResult = {
              revoked: result.revoked as string[],
              not_found: result.not_found as string[],
              already_revoked: result.already_revoked as string[]
            };
          }
        } catch {
          responseBodyHasResultShape = false;
        }
      }
    } catch {
      revocationResponseStatus = 0;
      responseContentType = '';
    }

    const expectedStatus = [207, 400, 401, 404, 429, 500, 503].includes(revocationResponseStatus);
    const responseCompatible =
      (revocationResponseStatus === 207 &&
        responseContentType.includes('application/json') &&
        responseBodyHasResultShape) ||
      (revocationResponseStatus !== 207 &&
        (responseContentType.includes('application/json') || responseContentType.includes('application/problem+json')));

    expect(
      expectedStatus && responseCompatible,
      `Wallet Provider must expose PDND revocation endpoint PATCH /wallet-instances with expected HTTP behavior`
    ).toBe(true);
  });

  // ___ WP_010 ____
  it('WP_010 - Wallet instance revocation terminates all instance operations', async () => {
    const candidateId =
      lastPdndRevocationResult?.revoked?.[0] ??
      lastPdndRevocationResult?.already_revoked?.[0] ??
      'itw-conformance-test-wallet-instance-id';

    const revocationEndpoint = `${walletProviderUrl}/wallet-instances/${encodeURIComponent(candidateId)}`;

    const revokeResponse = await fetch(revocationEndpoint, {
      method: 'PATCH',
      body: JSON.stringify({ status: 'REVOKED' }),
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(10_000)
    });

    const revocationAcknowledged = [200, 202, 204].includes(revokeResponse.status);

    let followupStatus = 0;
    try {
      const followupResponse = await fetch(`${walletProviderUrl}/verify-credential`, {
        method: 'POST',
        body: JSON.stringify({
          instance_id: candidateId,
          operation: 'verify_credential',
          data: {}
        }),
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(10_000)
      });
      followupStatus = followupResponse.status;
    } catch {
      followupStatus = 0;
    }

    const followupOperationBlocked = [401, 403, 404, 410].includes(followupStatus);

    expect(
      revocationAcknowledged && followupOperationBlocked,
      `Revoked Wallet Instance must be terminated and blocked from further operations. Revocation status ${revokeResponse.status}, post-revocation status ${followupStatus}`
    ).toBe(true);
  });
});
