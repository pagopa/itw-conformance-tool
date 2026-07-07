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
  verifyEntityStatementWithFederationJwks,
  type Jwk,
  type JwkSet
} from '@itw-conformance-tool/crypto';
import {
  itWalletMetadataV1_3,
  type ItWalletEntityConfigurationClaims,
  type ItWalletMetadataV1_3,
  type ItWalletSolutionEntityMetadataV1_3
} from '@pagopa/io-wallet-oid-federation';
import { calculateJwkThumbprint, decodeJwt, decodeProtectedHeader } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { isHttpsUrl, normalizeUrl } from '../../utils/url.js';

function hasJsonLikeJwksContentType(contentType: string): boolean {
  return contentType.includes('application/json') || contentType.includes('application/jwk-set+json');
}

async function fetchJwksFromUri(jwksUri: string): Promise<Jwk[]> {
  try {
    const response = await fetch(jwksUri, { signal: AbortSignal.timeout(5_000) });
    const contentType = response.headers.get('content-type') ?? '';
    if (response.status !== 200 || !hasJsonLikeJwksContentType(contentType)) {
      return [];
    }

    const body = (await response.json()) as { keys?: Jwk[] };
    return Array.isArray(body.keys) ? body.keys : [];
  } catch {
    return [];
  }
}

type HeaderMap = Record<string, string>;

async function resolveWalletSolutionKeys(
  walletSolution: ItWalletSolutionEntityMetadataV1_3,
  federationJwks: JwkSet
): Promise<Jwk[]> {
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
  // RFC 3230 style Digest header value: base64-encoded SHA-256 bytes.
  const digestB64 = createHash('sha256').update(body).digest('base64');
  return `SHA-256=${digestB64}`;
}

function hasProblemJsonContentType(contentType: string): boolean {
  return contentType.includes('application/problem+json');
}

function buildPdndRevocationHeaders(body: string): HeaderMap {
  const digest = buildSha256DigestHeader(body);
  const configuredAgidJwtSignature = process.env.ITW_CT_PDND_AGID_JWT_SIGNATURE?.trim();
  const configuredAuthorization = process.env.ITW_CT_PDND_AUTHORIZATION?.trim();
  const configuredDpop = process.env.ITW_CT_PDND_DPOP?.trim();
  const headers: HeaderMap = {
    'Content-Type': 'application/merge-patch+json',
    Digest: digest,
    'Agid-JWT-Signature': configuredAgidJwtSignature ?? 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.dGVzdA.dGVzdA'
  };

  if (configuredAuthorization && configuredAuthorization.length > 0) {
    headers.Authorization = configuredAuthorization;
  }
  if (configuredDpop && configuredDpop.length > 0) {
    headers.DPoP = configuredDpop;
  }

  return headers;
}

function parseJsonObject(text: string, context: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error: unknown) {
    throw new Error(`${context}: response body is not valid JSON`, { cause: error });
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${context}: response JSON must be an object`);
  }

  return parsed as Record<string, unknown>;
}

function hasExclusiveRevocationPartition(ids: string[], result: PdndRevocationResult): boolean {
  return ids.every((id) => {
    const membershipCount =
      Number(result.revoked.includes(id)) +
      Number(result.not_found.includes(id)) +
      Number(result.already_revoked.includes(id));

    return membershipCount === 1;
  });
}

type PdndRevocationResult = {
  revoked: string[];
  not_found: string[];
  already_revoked: string[];
};

type ParsedEntityConfiguration = {
  header: Record<string, unknown>;
  payload: ItWalletEntityConfigurationClaims;
  entityStatementSignatureValid: boolean;
};

let lastPdndRevocationResult: PdndRevocationResult | null = null;

describe.sequential(`Test Cases for Wallet Provider Backend`, () => {
  let walletProviderUrl: string;
  let entityConfigResponse: { statusCode: number; body: string };
  let parsedEntityConfiguration: ParsedEntityConfiguration | null = null;
  let parsedEntityConfigurationError: string | null = null;
  let parsedWalletMetadata: ItWalletMetadataV1_3 | null = null;
  let parsedWalletMetadataError: string | null = null;

  function requireParsedEntityConfiguration(): ParsedEntityConfiguration {
    if (parsedEntityConfiguration) {
      return parsedEntityConfiguration;
    }

    const setupErrorSuffix = parsedEntityConfigurationError ? `: ${parsedEntityConfigurationError}` : '';
    throw new Error(`Entity configuration setup failed${setupErrorSuffix}`);
  }

  function requireParsedWalletMetadata(): ItWalletMetadataV1_3 {
    requireParsedEntityConfiguration();
    if (parsedWalletMetadata) {
      return parsedWalletMetadata;
    }

    const metadataErrorSuffix = parsedWalletMetadataError ? `: ${parsedWalletMetadataError}` : '';
    throw new Error(`Entity configuration metadata validation failed${metadataErrorSuffix}`);
  }

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
      parsedEntityConfigurationError = 'Failed to fetch entity configuration';
      return;
    }

    if (!hasCompactJwtShape(entityConfigResponse.body)) {
      parsedEntityConfigurationError = 'Entity configuration response is not a compact JWT';
      return;
    }

    try {
      const header = decodeProtectedHeader(entityConfigResponse.body) as Record<string, unknown>;
      const payload = decodeJwt(entityConfigResponse.body) as ItWalletEntityConfigurationClaims;

      if (!payload.jwks || !Array.isArray(payload.jwks.keys) || payload.jwks.keys.length === 0) {
        parsedEntityConfigurationError = 'Entity configuration payload jwks is missing or empty';
        return;
      }

      const entityStatementSignatureValid = await verifyEntityStatementWithFederationJwks(
        entityConfigResponse.body,
        payload.jwks
      );

      parsedEntityConfiguration = {
        header,
        payload,
        entityStatementSignatureValid
      };

      const metadataParseResult = itWalletMetadataV1_3.safeParse(payload.metadata);
      if (metadataParseResult.success) {
        parsedWalletMetadata = metadataParseResult.data;
      } else {
        parsedWalletMetadataError = metadataParseResult.error.issues
          .map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
          .join('; ');
      }
    } catch (error: unknown) {
      parsedEntityConfigurationError = error instanceof Error ? error.message : 'Entity configuration decode failed';
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
    expect(
      parsedEntityConfigurationError,
      `Entity configuration must be decodable and include jwks for WP_002 prerequisites`
    ).toBeNull();

    if (!parsedEntityConfiguration) {
      const validationErrorSuffix = parsedEntityConfigurationError ? `: ${parsedEntityConfigurationError}` : '';
      throw new Error(`Entity configuration validation failed${validationErrorSuffix}`);
    }

    expect(
      parsedEntityConfiguration.entityStatementSignatureValid,
      `Entity configuration JWT signature is invalid`
    ).toBe(true);
  });

  it("WP_002a - 'alg' must be allowed and not 'none'", async () => {
    const { header } = requireParsedEntityConfiguration();
    const isValidAlg =
      typeof header.alg === 'string' &&
      ALLOWED_FEDERATION_JOSE_ALGORITHMS.includes(header.alg as (typeof ALLOWED_FEDERATION_JOSE_ALGORITHMS)[number]);

    expect(isValidAlg, `JWT header alg is missing, unsupported, or set to none`).toBe(true);
  });

  it("WP_002b - 'kid' must equal public key thumbprint", async () => {
    const { header, payload } = requireParsedEntityConfiguration();
    const hasJwks = Array.isArray(payload.jwks?.keys) && payload.jwks?.keys.length > 0;
    const foundJwk = payload.jwks?.keys?.find((key: Jwk) => key.kid === header.kid);
    const kidMatchesThumbprint = !!foundJwk && (await calculateJwkThumbprint(foundJwk)) === header.kid;
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
    const { header } = requireParsedEntityConfiguration();
    const isValidTyp = header.typ === 'entity-statement+jwt';

    expect(isValidTyp, `JWT header typ is missing or incorrect`).toBe(true);
  });

  it("WP_002d - 'iss' and 'sub' must be equal and valid HTTPS URLs", async () => {
    const { payload } = requireParsedEntityConfiguration();
    const hasIssuerString = typeof payload.iss === 'string';
    const hasSubjectString = typeof payload.sub === 'string';

    expect(hasIssuerString, `JWT payload iss must be present and be a string`).toBe(true);
    expect(hasSubjectString, `JWT payload sub must be present and be a string`).toBe(true);

    if (!hasIssuerString || !hasSubjectString) {
      return;
    }

    const issuer = payload.iss;
    const subject = payload.sub;
    const isValidIssuerHttps = isHttpsUrl(issuer);
    const isValidSubjectHttps = isHttpsUrl(subject);

    expect(isValidIssuerHttps, `JWT payload iss must be a valid HTTPS URL`).toBe(true);
    expect(isValidSubjectHttps, `JWT payload sub must be a valid HTTPS URL`).toBe(true);

    if (!isValidIssuerHttps || !isValidSubjectHttps) {
      return;
    }

    const normalizedIssuer = normalizeUrl(issuer);
    const normalizedSubject = normalizeUrl(subject);
    const issEqualsSubject = normalizedIssuer === normalizedSubject;
    const matchesWalletProviderUrl = normalizedIssuer === walletProviderUrl && normalizedSubject === walletProviderUrl;

    expect(issEqualsSubject, `JWT payload iss and sub must be equal after URL normalization`).toBe(true);
    expect(
      matchesWalletProviderUrl,
      `JWT payload iss/sub must match wallet provider public URL (iss=${normalizedIssuer}, sub=${normalizedSubject}, expected=${walletProviderUrl})`
    ).toBe(true);
  });

  it("WP_002e - 'iat' and 'exp' must be valid Unix timestamps and not expired", async () => {
    const { payload } = requireParsedEntityConfiguration();
    const clockSkewToleranceSeconds = 120;
    const nowUnix = Math.floor(Date.now() / 1000);
    const isValidIat = typeof payload.iat === 'number' && Number.isInteger(payload.iat) && payload.iat > 0;
    const isValidExp = typeof payload.exp === 'number' && Number.isInteger(payload.exp) && payload.exp > 0;
    const expAfterIat = isValidIat && isValidExp ? payload.exp > payload.iat : false;
    const isNotExpiredWithTolerance = isValidExp ? payload.exp >= nowUnix - clockSkewToleranceSeconds : false;

    expect(isValidIat, `JWT payload iat must be a valid positive Unix timestamp`).toBe(true);
    expect(isValidExp, `JWT payload exp must be a valid positive Unix timestamp`).toBe(true);
    expect(expAfterIat, `JWT payload exp must be greater than iat`).toBe(true);
    expect(
      isNotExpiredWithTolerance,
      `JWT payload exp must be in the future allowing ${clockSkewToleranceSeconds}s clock skew (exp=${String(payload.exp)}, now=${nowUnix})`
    ).toBe(true);
  });

  it("WP_002f - 'authority_hints' must be array of valid HTTPS URLs", async () => {
    const { payload } = requireParsedEntityConfiguration();
    const authorityHints = payload.authority_hints;
    const hasAuthorityHints = Array.isArray(authorityHints);
    const allValidAuthorityHints = hasAuthorityHints && authorityHints.length > 0 && authorityHints.every(isHttpsUrl);

    expect(
      allValidAuthorityHints,
      `JWT payload authority_hints must be a non-empty array of valid HTTPS URLs; trust-chain validation requires dedicated fixtures`
    ).toBe(true);
  });

  it("WP_002g - 'jwks' must contain valid JWK signing keys", async () => {
    const { payload } = requireParsedEntityConfiguration();
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
    const { payload } = requireParsedEntityConfiguration();
    const metadataValid = typeof payload.metadata === 'object' && payload.metadata !== null;

    expect(metadataValid, `JWT payload metadata must be present and be an object`).toBe(true);
    if (!metadataValid) {
      return;
    }

    const metadata = payload.metadata as Record<string, unknown>;
    const hasWalletSolution = typeof metadata.wallet_solution === 'object' && metadata.wallet_solution !== null;
    const hasFederationEntity = typeof metadata.federation_entity === 'object' && metadata.federation_entity !== null;
    const schemaErrorDetails = parsedWalletMetadataError ?? '';
    const metadataSchemaErrorMessage =
      'JWT payload metadata must be valid against io-wallet-sdk schemas' +
      (schemaErrorDetails.length > 0 ? `: ${schemaErrorDetails}` : '');

    expect(hasWalletSolution, `JWT payload metadata.wallet_solution must be present and be an object`).toBe(true);
    expect(hasFederationEntity, `JWT payload metadata.federation_entity must be present and be an object`).toBe(true);
    expect(!!parsedWalletMetadata, metadataSchemaErrorMessage).toBe(true);
  });

  // ___ WP_003 ____
  it('WP_003 - Public keys are used exclusively for signing/encryption in Wallet Provider role', async () => {
    const { payload } = requireParsedEntityConfiguration();
    const walletMetadata = requireParsedWalletMetadata();
    const walletSolution = walletMetadata.wallet_solution;
    const federationJwks = payload.jwks;
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
    const allKeysPublic = candidateKeys.every((key: Jwk) => hasNoPrivateJwkParams(key));
    const allKeysForSigningOrEncryption = candidateKeys.every((key: Jwk) => isKeySemanticallyConsistent(key));

    expect(
      allCandidateKeysValid && allKeysPublic && allKeysForSigningOrEncryption,
      `Wallet Provider keys must be valid public JWKs and restricted to signing/encryption semantics`
    ).toBe(true);
  });

  // ___ WP_004 ____
  it('WP_004 - Public keys are referenced with exactly one of jwks, jwks_uri, or signed_jwks_uri', async () => {
    const walletMetadata = requireParsedWalletMetadata();
    const walletSolution = walletMetadata.wallet_solution;
    const hasJwksRef = walletSolution?.jwks !== undefined;
    const hasJwksUriRef = walletSolution?.jwks_uri !== undefined;
    const hasSignedJwksUriRef = walletSolution?.signed_jwks_uri !== undefined;

    const count = [hasJwksRef, hasJwksUriRef, hasSignedJwksUriRef].filter(Boolean).length;
    const exactlyOne = count === 1;

    expect(exactlyOne, `Expected exactly one of metadata.wallet_solution.jwks/jwks_uri/signed_jwks_uri`).toBe(true);
  });

  it('WP_004a - jwks is a valid public JWKS document when present', async () => {
    const walletMetadata = requireParsedWalletMetadata();
    const walletSolution = walletMetadata.wallet_solution;
    const hasJwksRef = walletSolution?.jwks !== undefined;
    if (!hasJwksRef) {
      return;
    }

    const jwksValid = await isValidPublicJwks(walletSolution.jwks);

    expect(jwksValid, `metadata.wallet_solution.jwks must be a valid public JWKS document`).toBe(true);
  });

  it('WP_004b - jwks_uri is valid HTTPS and resolvable when present', async () => {
    const walletMetadata = requireParsedWalletMetadata();
    const walletSolution = walletMetadata.wallet_solution;
    const hasJwksUriRef = walletSolution?.jwks_uri !== undefined;
    if (!hasJwksUriRef) {
      return;
    }

    const jwksUri = walletSolution?.jwks_uri;
    const jwksUriValid = isHttpsUrl(jwksUri);
    let jwksUriResolvable = false;
    let jsonLikeContentType = false;
    let bodyHasJwks = false;
    let allKeysValid = false;

    if (jwksUriValid) {
      try {
        const response = await fetch(jwksUri as string, { signal: AbortSignal.timeout(5_000) });
        jwksUriResolvable = response.status === 200;
        jsonLikeContentType = hasJsonLikeJwksContentType(response.headers.get('content-type') ?? '');

        if (jwksUriResolvable && jsonLikeContentType) {
          const decoded = (await response.json()) as { keys?: Jwk[] };
          const keys = decoded.keys ?? [];
          bodyHasJwks = Array.isArray(keys) && keys.length > 0;
          allKeysValid = bodyHasJwks && (await isValidPublicJwks(decoded));
        }
      } catch {
        jwksUriResolvable = false;
      }
    }

    expect(
      jwksUriValid && jwksUriResolvable && jsonLikeContentType && bodyHasJwks && allKeysValid,
      `metadata.wallet_solution.jwks_uri must be HTTPS, return HTTP 200 JSON/JWK-SET+JSON, and contain valid JWKS`
    ).toBe(true);
  });

  it('WP_004c - signed_jwks_uri points to valid signed JWKS when present', async () => {
    const { payload } = requireParsedEntityConfiguration();
    const walletMetadata = requireParsedWalletMetadata();
    const walletSolution = walletMetadata.wallet_solution;
    const hasSignedJwksUriRef = walletSolution?.signed_jwks_uri !== undefined;
    if (!hasSignedJwksUriRef) {
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
    const headers = buildPdndRevocationHeaders(body);

    let revocationResponse: Response;
    try {
      revocationResponse = await fetch(revocationEndpoint, {
        method: 'PATCH',
        body,
        headers,
        signal: AbortSignal.timeout(10_000)
      });
    } catch (error: unknown) {
      throw new Error(`Failed to call PDND revocation endpoint PATCH ${revocationEndpoint}`, { cause: error });
    }

    const revocationResponseStatus = revocationResponse.status;
    const responseContentType = revocationResponse.headers.get('content-type') ?? '';
    const responseText = await revocationResponse.text();

    const expectedStatuses = [207, 400, 401, 404, 429, 500, 503];
    expect(
      expectedStatuses.includes(revocationResponseStatus),
      `Unexpected status ${revocationResponseStatus} from PDND revocation endpoint`
    ).toBe(true);

    if (revocationResponseStatus === 207) {
      expect(
        responseContentType.includes('application/json'),
        `207 response must use application/json content type`
      ).toBe(true);

      const parsed = parseJsonObject(responseText, 'PDND revocation 207 response');
      const result = parsed.result as Record<string, unknown> | undefined;
      const hasExpectedResultShape =
        typeof parsed.result_description === 'string' &&
        !!result &&
        Array.isArray(result.revoked) &&
        Array.isArray(result.not_found) &&
        Array.isArray(result.already_revoked);

      expect(
        hasExpectedResultShape,
        `207 response must include result_description and result.{revoked,not_found,already_revoked} arrays`
      ).toBe(true);

      if (!hasExpectedResultShape) {
        return;
      }

      const revocationResult: PdndRevocationResult = {
        revoked: result.revoked as string[],
        not_found: result.not_found as string[],
        already_revoked: result.already_revoked as string[]
      };

      expect(
        hasExclusiveRevocationPartition(walletInstanceIds, revocationResult),
        `Each requested wallet_instance_id must appear exactly once across revoked/not_found/already_revoked`
      ).toBe(true);

      const responseDigestHeader = revocationResponse.headers.get('digest') ?? '';
      const responseAgidJwtSignatureHeader = revocationResponse.headers.get('agid-jwt-signature') ?? '';
      expect(responseDigestHeader.length > 0, `207 response must include Digest header`).toBe(true);
      expect(responseAgidJwtSignatureHeader.length > 0, `207 response must include Agid-JWT-Signature header`).toBe(
        true
      );

      lastPdndRevocationResult = revocationResult;
      return;
    }

    expect(
      hasProblemJsonContentType(responseContentType),
      `Error responses must use application/problem+json content type`
    ).toBe(true);

    const problem = parseJsonObject(responseText, 'PDND revocation error response');
    const hasProblemShape =
      typeof problem.title === 'string' &&
      typeof problem.status === 'number' &&
      (problem.type === undefined || typeof problem.type === 'string');

    expect(hasProblemShape, `Error responses must comply with RFC7807 problem+json shape`).toBe(true);

    throw new Error(
      `WP_008 requires a successful authorized PDND revocation flow (HTTP 207); received ${revocationResponseStatus}. Configure valid PDND credentials (e.g. ITW_CT_PDND_AGID_JWT_SIGNATURE/ITW_CT_PDND_AUTHORIZATION/ITW_CT_PDND_DPOP).`
    );
  });

  // ___ WP_010 ____
  it('WP_010 - Wallet instance revocation terminates all instance operations', async () => {
    const candidateId =
      lastPdndRevocationResult?.revoked?.[0] ?? lastPdndRevocationResult?.already_revoked?.[0] ?? null;

    expect(candidateId, `WP_010 prerequisite failed: no wallet_instance_id available from WP_008`).toBeTruthy();
    if (!candidateId) {
      return;
    }

    const revocationEndpoint = `${walletProviderUrl}/wallet-instances`;
    const body = JSON.stringify({ wallet_instance_ids: [candidateId] });
    const headers = buildPdndRevocationHeaders(body);

    let followupResponse: Response;
    try {
      followupResponse = await fetch(revocationEndpoint, {
        method: 'PATCH',
        body,
        headers,
        signal: AbortSignal.timeout(10_000)
      });
    } catch (error: unknown) {
      throw new Error(`Failed to call PDND revocation endpoint PATCH ${revocationEndpoint}`, { cause: error });
    }

    const followupStatus = followupResponse.status;
    const followupContentType = followupResponse.headers.get('content-type') ?? '';
    const followupText = await followupResponse.text();

    expect(followupStatus, `WP_010 requires follow-up revocation to return HTTP 207`).toBe(207);
    if (followupStatus !== 207) {
      const hasProblemContentType = hasProblemJsonContentType(followupContentType);
      expect(hasProblemContentType, `Non-207 response must use application/problem+json content type`).toBe(true);
      throw new Error(
        `WP_010 requires a successful authorized follow-up revocation flow (HTTP 207); received ${followupStatus}. Configure valid PDND credentials (e.g. ITW_CT_PDND_AGID_JWT_SIGNATURE/ITW_CT_PDND_AUTHORIZATION/ITW_CT_PDND_DPOP).`
      );
    }

    expect(
      followupContentType.includes('application/json'),
      `207 response must use application/json content type`
    ).toBe(true);

    const parsed = parseJsonObject(followupText, 'PDND revocation follow-up 207 response');
    const result = parsed.result as Record<string, unknown> | undefined;
    const hasExpectedResultShape =
      typeof parsed.result_description === 'string' &&
      !!result &&
      Array.isArray(result.revoked) &&
      Array.isArray(result.not_found) &&
      Array.isArray(result.already_revoked);

    expect(
      hasExpectedResultShape,
      `207 follow-up response must include result_description and result.{revoked,not_found,already_revoked} arrays`
    ).toBe(true);
    if (!hasExpectedResultShape) {
      return;
    }

    const followupResult: PdndRevocationResult = {
      revoked: result.revoked as string[],
      not_found: result.not_found as string[],
      already_revoked: result.already_revoked as string[]
    };

    expect(
      hasExclusiveRevocationPartition([candidateId], followupResult),
      `Follow-up response must classify wallet_instance_id in exactly one of revoked/not_found/already_revoked`
    ).toBe(true);

    const isAlreadyRevoked = followupResult.already_revoked.includes(candidateId);
    expect(
      isAlreadyRevoked,
      `Revoked Wallet Instance must be reported as already_revoked on follow-up revocation request`
    ).toBe(true);
  });
});
