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
  itWalletEntityConfigurationClaimsSchema,
  itWalletMetadataV1_3,
  type ItWalletEntityConfigurationClaims,
  type ItWalletSolutionEntityMetadataV1_3
} from '@pagopa/io-wallet-oid-federation';
import { calculateJwkThumbprint, decodeJwt, decodeProtectedHeader } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { isHttpsUrl, normalizeUrl } from '../../utils/url.js';

type ParsedEntityConfiguration = {
  header: Record<string, unknown>;
  payload: ItWalletEntityConfigurationClaims;
  entityStatementSignatureValid: boolean;
};

type WalletMetadataLike = {
  wallet_solution?: ItWalletSolutionEntityMetadataV1_3;
  federation_entity?: unknown;
};

function parseMediaType(contentType: string): string {
  return contentType.split(';', 1)[0]?.trim().toLowerCase() ?? '';
}

function hasJsonLikeJwksContentType(contentType: string): boolean {
  const mediaType = parseMediaType(contentType);
  return mediaType === 'application/json' || mediaType === 'application/jwk-set+json';
}

function hasEntityStatementJwtContentType(contentType: string): boolean {
  return parseMediaType(contentType) === 'application/entity-statement+jwt';
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

describe.sequential(`Test Cases for Wallet Provider Backend`, () => {
  let walletProviderUrl: string;
  let entityConfigResponse: { statusCode: number; body: string; contentType: string };
  let parsedEntityConfiguration: ParsedEntityConfiguration | null = null;
  let parsedEntityConfigurationError: string | null = null;
  let parsedWalletMetadataError: string | null = null;
  let parsedWalletMetadataLike: WalletMetadataLike | null = null;

  function requireParsedEntityConfiguration(): ParsedEntityConfiguration {
    if (parsedEntityConfiguration) {
      return parsedEntityConfiguration;
    }

    const setupErrorSuffix = parsedEntityConfigurationError ? `: ${parsedEntityConfigurationError}` : '';
    throw new Error(`Entity configuration setup failed${setupErrorSuffix}`);
  }

  function requireParsedWalletMetadataLike(): WalletMetadataLike {
    requireParsedEntityConfiguration();
    if (parsedWalletMetadataLike) {
      return parsedWalletMetadataLike;
    }

    const metadataErrorSuffix = parsedWalletMetadataError ? `: ${parsedWalletMetadataError}` : '';
    throw new Error(`Entity configuration wallet metadata validation failed${metadataErrorSuffix}`);
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
      const contentType = rawResponse.headers.get('content-type') ?? '';
      entityConfigResponse = { statusCode: rawResponse.status, body: await rawResponse.text(), contentType };
    } catch {
      entityConfigResponse = { statusCode: 0, body: '', contentType: '' };
      parsedEntityConfigurationError = 'Failed to fetch entity configuration';
      return;
    }

    if (!hasCompactJwtShape(entityConfigResponse.body)) {
      parsedEntityConfigurationError = 'Entity configuration response is not a compact JWT';
      return;
    }

    let header: Record<string, unknown>;
    let decodedPayload: unknown;

    try {
      header = decodeProtectedHeader(entityConfigResponse.body) as Record<string, unknown>;
    } catch (error: unknown) {
      parsedEntityConfigurationError = `JWT header decode failed: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`;
      return;
    }

    try {
      decodedPayload = decodeJwt(entityConfigResponse.body);
    } catch (error: unknown) {
      parsedEntityConfigurationError = `JWT payload decode failed: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`;
      return;
    }

    const claimsWithoutMetadata =
      typeof decodedPayload === 'object' && decodedPayload !== null
        ? { ...(decodedPayload as Record<string, unknown>), metadata: undefined }
        : decodedPayload;

    const entityConfigurationClaimsParseResult =
      itWalletEntityConfigurationClaimsSchema.safeParse(claimsWithoutMetadata);
    if (!entityConfigurationClaimsParseResult.success) {
      const schemaIssues = entityConfigurationClaimsParseResult.error.issues
        .map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
        .join('; ');
      parsedEntityConfigurationError =
        'Entity configuration payload schema validation failed' + (schemaIssues.length > 0 ? `: ${schemaIssues}` : '');
      return;
    }

    const payload = {
      ...entityConfigurationClaimsParseResult.data,
      metadata:
        typeof decodedPayload === 'object' && decodedPayload !== null
          ? (decodedPayload as { metadata?: ItWalletEntityConfigurationClaims['metadata'] }).metadata
          : undefined
    } as ItWalletEntityConfigurationClaims;

    if (!payload.jwks) {
      parsedEntityConfigurationError = 'Entity configuration payload jwks is missing';
      return;
    }

    if (!Array.isArray(payload.jwks.keys)) {
      parsedEntityConfigurationError = 'Entity configuration payload jwks.keys is not an array';
      return;
    }

    if (payload.jwks.keys.length === 0) {
      parsedEntityConfigurationError = 'Entity configuration payload jwks.keys is empty';
      return;
    }

    let entityStatementSignatureValid: boolean;

    try {
      entityStatementSignatureValid = await verifyEntityStatementWithFederationJwks(
        entityConfigResponse.body,
        payload.jwks
      );
    } catch (error: unknown) {
      parsedEntityConfigurationError = `Entity statement signature verification failed: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`;
      return;
    }

    if (!entityStatementSignatureValid) {
      parsedEntityConfigurationError = 'Entity statement signature verification failed: signature is invalid';
      return;
    }

    parsedEntityConfiguration = {
      header,
      payload,
      entityStatementSignatureValid
    };

    const metadataParseResult = itWalletMetadataV1_3.safeParse(payload.metadata);
    if (metadataParseResult.success) {
      parsedWalletMetadataLike = {
        wallet_solution: metadataParseResult.data.wallet_solution,
        federation_entity: metadataParseResult.data.federation_entity
      };
    } else {
      parsedWalletMetadataError = metadataParseResult.error.issues
        .map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
        .join('; ');

      const rawMetadata =
        typeof payload.metadata === 'object' && payload.metadata !== null
          ? (payload.metadata as Record<string, unknown>)
          : null;
      const rawWalletSolution = rawMetadata?.wallet_solution;
      if (typeof rawWalletSolution === 'object' && rawWalletSolution !== null) {
        parsedWalletMetadataLike = {
          wallet_solution: rawWalletSolution as ItWalletSolutionEntityMetadataV1_3,
          federation_entity: rawMetadata?.federation_entity
        };
      }
    }
  });

  // ___ WP_001 ____
  it('WP_001 - Execute a GET request to /.well-known/openid-federation and returns 200', async () => {
    expect(entityConfigResponse.statusCode, `Expected /.well-known/openid-federation to return HTTP 200`).toBe(200);
    expect(
      hasEntityStatementJwtContentType(entityConfigResponse.contentType),
      `Expected Content-Type to be exactly application/entity-statement+jwt (ignoring parameters)`
    ).toBe(true);
  });

  // ___ WP_002 ____
  it('WP_002 - Entity configuration is an OpenID Federation-compliant signed JWT with all required components', async () => {
    const entityStatementSignatureValid = parsedEntityConfiguration?.entityStatementSignatureValid ?? false;

    expect(entityStatementSignatureValid, `Entity configuration JWT signature is invalid`).toBe(true);
  });

  it("WP_002a - 'alg' must be allowed and not 'none'", async () => {
    let decodedHeader: Record<string, unknown> | null = null;
    if (hasCompactJwtShape(entityConfigResponse.body)) {
      try {
        decodedHeader = decodeProtectedHeader(entityConfigResponse.body) as Record<string, unknown>;
      } catch {
        decodedHeader = null;
      }
    }

    const alg = decodedHeader?.alg;
    const hasAlgString = typeof alg === 'string';

    expect(hasAlgString, `JWT header alg must be present and be a string`).toBe(true);
    if (!hasAlgString) {
      return;
    }

    const isAllowedAlg = ALLOWED_FEDERATION_JOSE_ALGORITHMS.includes(
      alg as (typeof ALLOWED_FEDERATION_JOSE_ALGORITHMS)[number]
    );
    const isNotNone = alg !== 'none';

    expect(isAllowedAlg, `JWT header alg must be one of the allowed federation algorithms`).toBe(true);
    expect(isNotNone, `JWT header alg must not be 'none'`).toBe(true);
  });

  it("WP_002b - 'kid' must equal public key thumbprint", async () => {
    let decodedHeader: Record<string, unknown> | null = null;
    let decodedPayload: unknown;

    if (hasCompactJwtShape(entityConfigResponse.body)) {
      try {
        decodedHeader = decodeProtectedHeader(entityConfigResponse.body) as Record<string, unknown>;
        decodedPayload = decodeJwt(entityConfigResponse.body);
      } catch {
        decodedHeader = null;
        decodedPayload = undefined;
      }
    }

    const kid = decodedHeader?.kid;
    const hasKidString = typeof kid === 'string';
    expect(hasKidString, `JWT header kid must be present and be a string`).toBe(true);

    const payloadJwks =
      typeof decodedPayload === 'object' && decodedPayload !== null
        ? ((decodedPayload as { jwks?: unknown }).jwks as JwkSet | undefined)
        : undefined;
    const hasJwks = Array.isArray(payloadJwks?.keys) && payloadJwks.keys.length > 0;
    const foundJwk = hasKidString ? payloadJwks?.keys?.find((key: Jwk) => key.kid === kid) : undefined;

    expect(hasJwks, `Entity configuration payload must contain a non-empty jwks before checking kid`).toBe(true);
    expect(!!foundJwk, `JWT header kid must match one of the keys in payload.jwks`).toBe(true);
    if (!foundJwk) {
      return;
    }

    const kidMatchesThumbprint = hasKidString ? (await calculateJwkThumbprint(foundJwk)) === kid : false;

    expect(kidMatchesThumbprint, `JWT header kid must equal the matched JWK thumbprint`).toBe(true);
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
    expect(hasAuthorityHints, `JWT payload authority_hints must be an array`).toBe(true);
    if (!hasAuthorityHints) {
      return;
    }

    expect(authorityHints.length > 0, `JWT payload authority_hints must not be empty`).toBe(true);
    expect(
      authorityHints.every(isHttpsUrl),
      `JWT payload authority_hints must contain only valid HTTPS URLs; trust-chain validation requires dedicated fixtures`
    ).toBe(true);
  });

  it("WP_002g - 'jwks' must contain valid JWK signing keys", async () => {
    const { payload } = requireParsedEntityConfiguration();
    const jwksKeys = payload.jwks?.keys ?? [];
    const hasJwks = Array.isArray(payload.jwks?.keys) && payload.jwks.keys.length > 0;
    expect(hasJwks, `JWT payload jwks must be present and non-empty`).toBe(true);
    if (!hasJwks || !payload.jwks) {
      return;
    }

    const jwksStructurallyValid = await isValidPublicJwks(payload.jwks);
    const hasPublicSigningKey = jwksKeys.some((key) => isPublicSigningJwk(key));
    const signatureVerified = await verifyEntityStatementWithFederationJwks(entityConfigResponse.body, payload.jwks);

    expect(jwksStructurallyValid, `JWT payload jwks must be structurally valid`).toBe(true);
    expect(hasPublicSigningKey, `JWT payload jwks must contain at least one public signing key`).toBe(true);
    expect(signatureVerified, `JWT payload jwks must verify the entity statement signature`).toBe(true);
  });

  it("WP_002h - 'metadata' must contain required wallet_solution field; federation_entity is optional", async () => {
    const { payload } = requireParsedEntityConfiguration();
    const metadataValid = typeof payload.metadata === 'object' && payload.metadata !== null;

    expect(metadataValid, `JWT payload metadata must be present and be an object`).toBe(true);
    if (!metadataValid) {
      return;
    }

    const metadata = payload.metadata as Record<string, unknown>;
    const hasWalletSolution = typeof metadata.wallet_solution === 'object' && metadata.wallet_solution !== null;
    const federationEntityIfPresentIsObject =
      !('federation_entity' in metadata) ||
      (typeof metadata.federation_entity === 'object' && metadata.federation_entity !== null);
    const schemaErrorDetails = parsedWalletMetadataError ?? '';
    const metadataSchemaErrorMessage =
      'JWT payload metadata must be a valid schema' + (schemaErrorDetails.length > 0 ? `: ${schemaErrorDetails}` : '');

    expect(hasWalletSolution, `JWT payload metadata.wallet_solution must be present and be an object`).toBe(true);
    expect(
      federationEntityIfPresentIsObject,
      `JWT payload metadata.federation_entity must be an object when present`
    ).toBe(true);
    const hasWalletMetadataLike = !!parsedWalletMetadataLike;
    expect(hasWalletMetadataLike, metadataSchemaErrorMessage).toBe(true);
  });

  // ___ WP_003 ____
  it('WP_003 - Public keys are used exclusively for signing/encryption in Wallet Provider role', async () => {
    const { payload } = requireParsedEntityConfiguration();
    const walletMetadata = requireParsedWalletMetadataLike();
    const walletSolution = walletMetadata.wallet_solution;
    const federationJwks = payload.jwks;
    const hasWalletSolution = typeof walletSolution === 'object' && walletSolution !== null;
    const hasFederationJwks = !!federationJwks && Array.isArray(federationJwks.keys) && federationJwks.keys.length > 0;

    expect(hasWalletSolution, `Entity configuration must expose metadata.wallet_solution`).toBe(true);
    expect(hasFederationJwks, `Entity configuration must expose a non-empty federation jwks`).toBe(true);
    if (!hasWalletSolution || !hasFederationJwks) {
      return;
    }

    const candidateKeys = await resolveWalletSolutionKeys(walletSolution, federationJwks);

    expect(
      candidateKeys.length > 0,
      `No wallet_solution keys could be resolved from jwks, jwks_uri, or signed_jwks_uri`
    ).toBe(true);

    if (candidateKeys.length === 0) {
      return;
    }

    const allCandidateKeysValid = (await Promise.all(candidateKeys.map(isValidJwk))).every(Boolean);
    const allKeysPublic = candidateKeys.every((key: Jwk) => hasNoPrivateJwkParams(key));
    const allKeysForSigningOrEncryption = candidateKeys.every((key: Jwk) => isKeySemanticallyConsistent(key));

    expect(allCandidateKeysValid, `Wallet Provider keys must be valid JWKs`).toBe(true);
    expect(allKeysPublic, `Wallet Provider keys must not contain private JWK parameters`).toBe(true);
    expect(
      allKeysForSigningOrEncryption,
      `Wallet Provider keys must be restricted to signing/encryption semantics`
    ).toBe(true);
  });

  // ___ WP_004 ____
  it('WP_004 - Public keys are referenced with exactly one of jwks, jwks_uri, or signed_jwks_uri', async () => {
    const walletMetadata = requireParsedWalletMetadataLike();
    const walletSolution = walletMetadata.wallet_solution;
    const hasJwksRef = walletSolution?.jwks !== undefined;
    const hasJwksUriRef = walletSolution?.jwks_uri !== undefined;
    const hasSignedJwksUriRef = walletSolution?.signed_jwks_uri !== undefined;

    expect(
      hasJwksRef || hasJwksUriRef || hasSignedJwksUriRef,
      `Expected at least one of metadata.wallet_solution.jwks/jwks_uri/signed_jwks_uri`
    ).toBe(true);
    expect(
      !(hasJwksRef && hasJwksUriRef),
      `metadata.wallet_solution.jwks and metadata.wallet_solution.jwks_uri must not both be present`
    ).toBe(true);
    expect(
      !(hasJwksRef && hasSignedJwksUriRef),
      `metadata.wallet_solution.jwks and metadata.wallet_solution.signed_jwks_uri must not both be present`
    ).toBe(true);
    expect(
      !(hasJwksUriRef && hasSignedJwksUriRef),
      `metadata.wallet_solution.jwks_uri and metadata.wallet_solution.signed_jwks_uri must not both be present`
    ).toBe(true);
  });

  it('WP_004a - jwks is a valid public JWKS document when present', async () => {
    const walletMetadata = requireParsedWalletMetadataLike();
    const walletSolution = walletMetadata.wallet_solution;
    const hasJwksRef = walletSolution?.jwks !== undefined;
    if (!hasJwksRef) {
      return;
    }

    const jwksValid = await isValidPublicJwks(walletSolution.jwks);

    expect(jwksValid, `metadata.wallet_solution.jwks must be a valid public JWKS document`).toBe(true);
  });

  it('WP_004b - jwks_uri is valid HTTPS and resolvable when present', async () => {
    const walletMetadata = requireParsedWalletMetadataLike();
    const walletSolution = walletMetadata.wallet_solution;
    const hasJwksUriRef = walletSolution?.jwks_uri !== undefined;
    if (!hasJwksUriRef) {
      return;
    }

    const jwksUri = walletSolution?.jwks_uri;
    const jwksUriIsString = typeof jwksUri === 'string';
    expect(jwksUriIsString, `metadata.wallet_solution.jwks_uri must be a string when present`).toBe(true);
    if (!jwksUriIsString) {
      return;
    }

    const jwksUriValid = isHttpsUrl(jwksUri);
    expect(jwksUriValid, `metadata.wallet_solution.jwks_uri must be a valid HTTPS URL`).toBe(true);

    let response: Response;

    try {
      response = await fetch(jwksUri, { signal: AbortSignal.timeout(5_000) });
    } catch (error: unknown) {
      throw new Error(
        `metadata.wallet_solution.jwks_uri must be resolvable: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }

    const jwksUriResolvable = response.status === 200;
    expect(jwksUriResolvable, `metadata.wallet_solution.jwks_uri must return HTTP 200`).toBe(true);

    const jsonLikeContentType = hasJsonLikeJwksContentType(response.headers.get('content-type') ?? '');
    expect(jsonLikeContentType, `metadata.wallet_solution.jwks_uri must return JSON or application/jwk-set+json`).toBe(
      true
    );

    if (jwksUriResolvable && jsonLikeContentType) {
      let decodedBody: unknown;
      try {
        decodedBody = await response.json();
      } catch (error: unknown) {
        throw new Error(
          `metadata.wallet_solution.jwks_uri must return valid JSON when HTTP 200 and JSON content-type are satisfied: ${
            error instanceof Error ? error.message : 'Unknown error'
          }`
        );
      }

      const decoded = decodedBody as { keys?: Jwk[] };
      const keys = decoded.keys ?? [];
      const bodyHasJwks = Array.isArray(keys) && keys.length > 0;
      expect(bodyHasJwks, `metadata.wallet_solution.jwks_uri response body must include a non-empty keys array`).toBe(
        true
      );

      if (bodyHasJwks) {
        const allKeysValid = await isValidPublicJwks(decoded);
        expect(allKeysValid, `metadata.wallet_solution.jwks_uri response must contain valid public JWKS keys`).toBe(
          true
        );
      }
    }
  });

  it('WP_004c - signed_jwks_uri points to valid signed JWKS when present', async () => {
    const { payload } = requireParsedEntityConfiguration();
    const walletMetadata = requireParsedWalletMetadataLike();
    const walletSolution = walletMetadata.wallet_solution;
    const hasSignedJwksUriRef = walletSolution?.signed_jwks_uri !== undefined;
    if (!hasSignedJwksUriRef) {
      return;
    }

    const signedJwksUri = walletSolution?.signed_jwks_uri;
    const signedJwksUriIsString = typeof signedJwksUri === 'string';
    expect(signedJwksUriIsString, `metadata.wallet_solution.signed_jwks_uri must be a string when present`).toBe(true);
    if (!signedJwksUriIsString) {
      return;
    }

    const signedJwksUriValid = isHttpsUrl(signedJwksUri);
    expect(signedJwksUriValid, `metadata.wallet_solution.signed_jwks_uri must be a valid HTTPS URL`).toBe(true);

    const hasFederationJwks = !!payload.jwks && Array.isArray(payload.jwks.keys) && payload.jwks.keys.length > 0;
    expect(
      hasFederationJwks,
      `Entity configuration must expose a non-empty federation jwks for signed_jwks_uri validation`
    ).toBe(true);

    if (!hasFederationJwks || !payload.jwks) {
      return;
    }

    const signedValidation = await validateSignedJwksUri(signedJwksUri, payload.jwks);

    expect(signedValidation.uriResolvable, `metadata.wallet_solution.signed_jwks_uri must resolve successfully`).toBe(
      true
    );
    expect(
      signedValidation.contentTypeValid,
      `metadata.wallet_solution.signed_jwks_uri must return application/jwk-set+jwt`
    ).toBe(true);
    expect(signedValidation.compactJwt, `metadata.wallet_solution.signed_jwks_uri response must be a compact JWT`).toBe(
      true
    );
    expect(
      signedValidation.payloadHasJwks,
      `metadata.wallet_solution.signed_jwks_uri JWT payload must include jwks`
    ).toBe(true);
    expect(
      signedValidation.signatureValid,
      `metadata.wallet_solution.signed_jwks_uri JWT signature must verify with federation jwks`
    ).toBe(true);
    expect(
      signedValidation.jwksValid,
      `metadata.wallet_solution.signed_jwks_uri JWT payload must contain a valid public JWKS document`
    ).toBe(true);
  });
});
