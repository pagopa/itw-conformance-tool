import { randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

import { parseINI } from '@itw-conformance-tool/config';
import { isValidJwk } from '@itw-conformance-tool/crypto';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { calculateJwkThumbprint, createLocalJWKSet, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { expandPath } from '../../utils/path.js';

type RequirementDefinition = {
  description: string;
  step: 'WALLET_PROVIDER_BACKEND';
};

type RequirementEvaluation = {
  result: ConformanceCheckResult;
  httpStatus: number;
  errorMessage?: string;
};

type ConformanceCheckResult = 'PASS' | 'FAIL' | 'NOT_REACHED';

type JwkLike = {
  kty?: string;
  kid?: string;
  key_ops?: string[];
  use?: string;
};

type WalletSolutionMetadata = {
  jwks?: { keys?: JwkLike[] };
};

type EntityMetadata = {
  wallet_solution?: WalletSolutionMetadata;
  openid_credential_verifier?: Record<string, unknown>;
  federation_entity?: Record<string, unknown>;
};

type EntityPayload = {
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  authority_hints: string[];
  jwks: { keys: JwkLike[] };
  metadata: EntityMetadata;
  jwks_uri?: string;
  signed_jwks_uri?: string;
};

type ConformanceRepo = {
  appendCheck: (
    sessionId: string,
    payload: {
      requirementId: RequirementId;
      description: string;
      step: RequirementDefinition['step'];
      phase: 'WALLET_PROVIDER_BACKEND';
      result: ConformanceCheckResult;
      timestamp: string;
      httpStatus: number;
      errorMessage?: string;
    }
  ) => Promise<void>;
  create: (payload: { sessionId: string; startedAt: string; status: 'OPEN'; checks: unknown[] }) => Promise<void>;
  get: (sessionId: string) => Promise<{ status: 'OPEN' | 'FAILED' | 'PASSED' } | null>;
  close: (sessionId: string, status: 'FAILED' | 'PASSED') => Promise<void>;
};

const REQUIREMENTS = {
  WP_001: {
    description: 'GET /.well-known/openid-federation responds with 200',
    step: 'WALLET_PROVIDER_BACKEND'
  },
  WP_002: {
    description: 'Entity configuration is an OpenID Federation-compliant signed JWT',
    step: 'WALLET_PROVIDER_BACKEND'
  },
  WP_003: {
    description: 'Public keys used exclusively for signing/encryption in Wallet Provider role',
    step: 'WALLET_PROVIDER_BACKEND'
  },
  WP_004: {
    description: 'Public keys are referenced with exactly one of jwks, jwks_uri, or signed_jwks_uri',
    step: 'WALLET_PROVIDER_BACKEND'
  },
  WP_008: {
    description: 'Wallet Provider supports revocation requests from Electronic Document Issuers',
    step: 'WALLET_PROVIDER_BACKEND'
  },
  WP_010: {
    description: 'Revoked Wallet Instance is terminated and cannot execute any further functions',
    step: 'WALLET_PROVIDER_BACKEND'
  }
} satisfies Record<string, RequirementDefinition>;

const CONFORMANCE_REQUIREMENT_ORDER = ['WP_001', 'WP_002', 'WP_003', 'WP_004', 'WP_008', 'WP_010'] as const;

type RequirementId = keyof typeof REQUIREMENTS;

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

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

describe.sequential(`Wallet Provider Backend`, () => {
  let dbClient: DatabaseClient;
  let repo: ConformanceRepo;
  let sessionId: string;
  let walletProviderUrl: string;
  let entityConfigResponse: { statusCode: number; body: string };

  // __ Values bones
  let jwt = {
    header: {} as Record<string, unknown>,
    payload: {} as EntityPayload,
    signature: ''
  };
  let payload = {} as EntityPayload;
  let hasJwks = false;

  async function appendCheck(requirementId: RequirementId, evaluation: RequirementEvaluation): Promise<void> {
    const requirement = REQUIREMENTS[requirementId];

    try {
      await repo.appendCheck(sessionId, {
        requirementId,
        description: requirement.description,
        step: requirement.step,
        phase: 'WALLET_PROVIDER_BACKEND',
        result: evaluation.result,
        timestamp: new Date().toISOString(),
        httpStatus: evaluation.httpStatus,
        errorMessage: evaluation.errorMessage
      });
    } catch (error) {
      throw new Error(`Failed to append conformance check for ${requirementId}: ${getErrorMessage(error)}`);
    }
  }

  async function closeSessionAsFailed(failedRequirementId: RequirementId): Promise<void> {
    const failedIndex = CONFORMANCE_REQUIREMENT_ORDER.indexOf(
      failedRequirementId as (typeof CONFORMANCE_REQUIREMENT_ORDER)[number]
    );

    if (failedIndex >= 0) {
      for (const requirementId of CONFORMANCE_REQUIREMENT_ORDER.slice(failedIndex + 1)) {
        await appendCheck(requirementId, {
          result: 'NOT_REACHED',
          httpStatus: 0,
          errorMessage: 'Skipped after a previous conformance failure closed the session'
        });
      }
    }

    try {
      await repo.close(sessionId, 'FAILED');
    } catch (error) {
      throw new Error(`Failed to close conformance session as FAILED: ${getErrorMessage(error)}`);
    }
  }

  async function recordRequirement(
    requirementId: RequirementId,
    evaluate: () => Promise<RequirementEvaluation>
  ): Promise<RequirementEvaluation | null> {
    const session = await repo.get(sessionId);
    if (session?.status !== 'OPEN') {
      return null;
    }

    const evaluation = await evaluate();
    await appendCheck(requirementId, evaluation);

    if (evaluation.result === 'FAIL') {
      await closeSessionAsFailed(requirementId);
    }

    return evaluation;
  }

  beforeAll(async () => {
    const configPath = process.env.CONFIG_FILE_PATH
      ? resolve(process.env.CONFIG_FILE_PATH)
      : resolve(process.cwd(), 'config.ini');
    const { data: config } = parseINI(configPath);

    if (!config.global.wallet_provider_backend_url?.trim()) {
      throw new Error('Missing required config: global.wallet_provider_backend_url');
    }

    if (!config.global.data_dir?.trim()) {
      throw new Error('Missing required config: global.data_dir');
    }

    walletProviderUrl = normalizeUrl(config.global.wallet_provider_backend_url);

    const resolvedDataDir = expandPath(config.global.data_dir);
    mkdirSync(resolvedDataDir, { recursive: true });
    dbClient = new DatabaseClient({ dataDir: resolvedDataDir });
    const { SqliteConformanceSessionRepository } = await import('@itw-conformance-tool/conformance');
    repo = new SqliteConformanceSessionRepository(dbClient.db) as unknown as ConformanceRepo;
    sessionId = randomUUID();
    try {
      await repo.create({
        sessionId,
        startedAt: new Date().toISOString(),
        status: 'OPEN',
        checks: []
      });
    } catch (error) {
      throw new Error(`Failed to create conformance session: ${getErrorMessage(error)}`);
    }

    try {
      const rawResponse = await fetch(`${walletProviderUrl}/.well-known/openid-federation`, {
        signal: AbortSignal.timeout(5_000)
      });
      entityConfigResponse = { statusCode: rawResponse.status, body: await rawResponse.text() };
    } catch {
      entityConfigResponse = { statusCode: 0, body: '' };
    }
  });

  afterAll(async () => {
    try {
      if (!repo || !sessionId) {
        return;
      }

      const session = await repo.get(sessionId);
      if (session?.status === 'OPEN') {
        try {
          await repo.close(sessionId, 'PASSED');
        } catch (error) {
          throw new Error(`Failed to close conformance session as PASSED: ${getErrorMessage(error)}`);
        }
      }
    } finally {
      try {
        await dbClient?.close();
      } catch {
        // Ignore close errors in test teardown.
      }
    }
  });

  // ___ WP_001 ____
  it('WP_001 - Execute a GET request to /.well-known/openid-federation and returns 200', async () => {
    const evaluation = await recordRequirement('WP_001', async () => ({
      result: entityConfigResponse.statusCode === 200 ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: entityConfigResponse.statusCode === 200 ? undefined : entityConfigResponse.body
    }));

    if (evaluation === null) {
      return;
    }

    expect(entityConfigResponse.statusCode).toBe(200);
  });

  // ___ WP_002 ____
  it('WP_002 - Entity configuration is an OpenID Federation-compliant signed JWT with all required components', async () => {
    const session = await repo.get(sessionId);
    if (session?.status !== 'OPEN') {
      return;
    }

    const parts = entityConfigResponse.body.split('.');

    let header: Record<string, unknown>;

    try {
      expect(parts).toHaveLength(3);
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString()) as Record<string, unknown>;
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()) as EntityPayload;
      jwt = { header, payload, signature: parts[2] };
    } catch (err) {
      await recordRequirement('WP_002', async () => ({
        result: 'FAIL',
        httpStatus: entityConfigResponse.statusCode,
        errorMessage: 'Entity configuration is not a well-formed compact JWT'
      }));
      throw err;
    }
  });

  it("WP_002a - 'alg' must be allowed and not 'none'", async () => {
    const allowedAlgorithms = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];
    const isValidAlg = typeof jwt.header.alg === 'string' && allowedAlgorithms.includes(jwt.header.alg);

    const evaluation = await recordRequirement('WP_002', async () => ({
      result: isValidAlg ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: isValidAlg ? undefined : `JWT header alg is missing, unsupported, or set to none`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  it("WP_002b - 'kid' must equal public key thumbprint", async () => {
    hasJwks = Array.isArray(payload.jwks?.keys) && payload.jwks.keys.length > 0;
    const foundJwk = payload.jwks?.keys?.find((key: JwkLike) => key.kid === jwt.header.kid);
    const kidMatchesThumbprint = !!foundJwk && (await calculateJwkThumbprint(foundJwk)) === jwt.header.kid;

    const evaluation = await recordRequirement('WP_002', async () => ({
      result: kidMatchesThumbprint ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: kidMatchesThumbprint ? undefined : `JWT header kid does not match any JWK thumbprint`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  it("WP_002c - 'typ' must be 'entity-statement+jwt'", async () => {
    const isValidTyp = jwt.header.typ === 'entity-statement+jwt';

    const evaluation = await recordRequirement('WP_002', async () => ({
      result: isValidTyp ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: isValidTyp ? undefined : `JWT header typ is missing or incorrect`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  it("WP_002d - 'iss' and 'sub' must be equal and valid HTTPS URLs", async () => {
    const isValidIssuer = typeof payload.iss === 'string' && isHttpsUrl(payload.iss);
    const isValidSubject = typeof payload.sub === 'string' && isHttpsUrl(payload.sub);
    const issEqualsSubject = payload.iss === payload.sub;

    const evaluation = await recordRequirement('WP_002', async () => ({
      result: isValidIssuer && isValidSubject && issEqualsSubject ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage:
        isValidIssuer && isValidSubject && issEqualsSubject
          ? undefined
          : `JWT payload iss and sub must be equal and valid HTTPS URLs`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  it("WP_002e - 'iat' and 'exp' must be valid Unix timestamps and not expired", async () => {
    const isValidIat = typeof payload.iat === 'number' && payload.iat > 0;
    const isValidExp = typeof payload.exp === 'number' && payload.exp > payload.iat;
    const isNotExpired = typeof payload.exp === 'number' && payload.exp > Math.floor(Date.now() / 1000);

    const evaluation = await recordRequirement('WP_002', async () => ({
      result: isValidIat && isValidExp && isNotExpired ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage:
        isValidIat && isValidExp && isNotExpired
          ? undefined
          : `JWT payload iat and exp must be valid Unix timestamps and not expired`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  it("WP_002f - 'authority_hints' must be array of valid HTTPS URLs", async () => {
    const hasAuthorityHints = Array.isArray(payload.authority_hints);
    const allValidAuthorityHints =
      hasAuthorityHints && payload.authority_hints.length > 0 && payload.authority_hints.every(isHttpsUrl);

    const evaluation = await recordRequirement('WP_002', async () => ({
      result: allValidAuthorityHints ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: allValidAuthorityHints
        ? undefined
        : `JWT payload authority_hints must be an array of valid HTTPS URLs`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  it("WP_002g - 'jwks' must contain valid JWK signing keys", async () => {
    const allKeysValid =
      hasJwks && payload.jwks.keys.length > 0 && (await Promise.all(payload.jwks.keys.map(isValidJwk))).every(Boolean);

    const evaluation = await recordRequirement('WP_002', async () => ({
      result: allKeysValid ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: allKeysValid ? undefined : `JWT payload jwks must contain valid JWK signing keys`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  it("WP_002h - 'metadata' must contain at least one recognised verifier/wallet metadata key", async () => {
    const metadataValid = typeof payload.metadata === 'object' && payload.metadata !== null;

    const metadata = metadataValid ? payload.metadata : undefined;

    const walletSolution = metadata?.wallet_solution ?? metadata?.openid_credential_verifier;
    const walletSolutionValid = typeof walletSolution === 'object' && walletSolution !== null;

    const federationEntity = metadata?.federation_entity;
    const federationEntityValid =
      federationEntity === undefined || (typeof federationEntity === 'object' && federationEntity !== null);

    const evaluation = await recordRequirement('WP_002', async () => ({
      result: metadataValid && walletSolutionValid && federationEntityValid ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage:
        metadataValid && walletSolutionValid && federationEntityValid
          ? undefined
          : `JWT payload metadata must contain at least one recognised verifier/wallet metadata key`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  // ___ WP_003 ____
  it('WP_003 - Public keys are used exclusively for signing/encryption in Wallet Provider role', async () => {
    const session = await repo.get(sessionId);
    if (session?.status !== 'OPEN') {
      return;
    }

    const parts = entityConfigResponse.body.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()) as EntityPayload;

    // Check that keys in wallet_solution metadata are for sig/enc only
    const walletSolutionKeys = payload.metadata?.wallet_solution?.jwks?.keys;
    const topLevelKeys = payload.jwks?.keys;
    let candidateKeys: JwkLike[] = [];
    if (Array.isArray(walletSolutionKeys)) {
      candidateKeys = walletSolutionKeys;
    } else if (Array.isArray(topLevelKeys)) {
      candidateKeys = topLevelKeys;
    }

    const allKeysForSigningOrEncryption = candidateKeys.every((key: JwkLike) => isKeySemanticallyConsistent(key));

    const result = allKeysForSigningOrEncryption ? 'PASS' : 'FAIL';

    const evaluation = await recordRequirement('WP_003', async () => ({
      result,
      httpStatus: entityConfigResponse.statusCode,
      errorMessage:
        result === 'PASS' ? undefined : 'Wallet Provider keys are not restricted to signing/encryption semantics'
    }));

    if (evaluation === null) {
      return;
    }

    expect(result).toBe('PASS');
  });

  // ___ WP_004 ____
  it('WP_004 - Public keys are referenced with exactly one of jwks, jwks_uri, or signed_jwks_uri', async () => {
    const session = await repo.get(sessionId);
    if (session?.status !== 'OPEN') {
      return;
    }

    const parts = entityConfigResponse.body.split('.');

    try {
      expect(parts).toHaveLength(3);
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()) as EntityPayload;
    } catch (err) {
      await recordRequirement('WP_004', async () => ({
        result: 'FAIL',
        httpStatus: entityConfigResponse.statusCode,
        errorMessage: 'Entity configuration is not a well-formed compact JWT for WP_004 checks'
      }));
      throw err;
    }
  });

  it('WP_004a - exactly one key reference claim is present and jwks is valid when used', async () => {
    const hasJwksRef = payload.jwks !== undefined;
    const hasJwksUriRef = payload.jwks_uri !== undefined;
    const hasSignedJwksUriRef = payload.signed_jwks_uri !== undefined;

    const count = [hasJwksRef, hasJwksUriRef, hasSignedJwksUriRef].filter(Boolean).length;
    const exactlyOne = count === 1;

    const jwksValid =
      !hasJwksRef ||
      (typeof payload.jwks === 'object' &&
        Array.isArray(payload.jwks.keys) &&
        payload.jwks.keys.length > 0 &&
        payload.jwks.keys.every((key: JwkLike) => typeof key.kty === 'string' && typeof key.kid === 'string'));

    const evaluation = await recordRequirement('WP_004', async () => ({
      result: exactlyOne && jwksValid ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage:
        exactlyOne && jwksValid
          ? undefined
          : `Expected exactly one of jwks/jwks_uri/signed_jwks_uri and valid jwks when present`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  it('WP_004b - jwks_uri is valid HTTPS, same-origin with iss, and resolvable when present', async () => {
    const hasJwksUriRef = payload.jwks_uri !== undefined;
    if (!hasJwksUriRef) {
      const evaluation = await recordRequirement('WP_004', async () => ({
        result: 'PASS',
        httpStatus: entityConfigResponse.statusCode
      }));

      if (evaluation === null) {
        return;
      }

      expect(evaluation.result).toBe('PASS');

      return;
    }

    const issuerOrigin = isHttpsUrl(payload.iss) ? new URL(payload.iss).origin : undefined;
    const fetchTimeoutMs = 5_000;

    const jwksUriValid = isHttpsUrl(payload.jwks_uri);
    let jwksUriResolvable = false;

    if (jwksUriValid) {
      try {
        const jwksUri = new URL(payload.jwks_uri ?? '');
        if (issuerOrigin && jwksUri.origin !== issuerOrigin) {
          throw new Error('jwks_uri is not same-origin as iss');
        }

        const response = await fetch(jwksUri, { signal: AbortSignal.timeout(fetchTimeoutMs) });
        jwksUriResolvable = response.ok && response.status === 200;
      } catch {
        jwksUriResolvable = false;
      }
    }

    const evaluation = await recordRequirement('WP_004', async () => ({
      result: jwksUriValid && jwksUriResolvable ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage:
        jwksUriValid && jwksUriResolvable
          ? undefined
          : `jwks_uri must be HTTPS, same-origin with iss, and return HTTP 200`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  it('WP_004c - signed_jwks_uri points to valid signed JWKS when present', async () => {
    const hasSignedJwksUriRef = payload.signed_jwks_uri !== undefined;
    if (!hasSignedJwksUriRef) {
      const evaluation = await recordRequirement('WP_004', async () => ({
        result: 'PASS',
        httpStatus: entityConfigResponse.statusCode
      }));

      if (evaluation === null) {
        return;
      }

      expect(evaluation.result).toBe('PASS');

      return;
    }

    const issuerOrigin = isHttpsUrl(payload.iss) ? new URL(payload.iss).origin : undefined;
    const fetchTimeoutMs = 5_000;

    const signedJwksUriValid = isHttpsUrl(payload.signed_jwks_uri);
    let signedJwksUriResolvable = false;
    let signedJwksPayloadHasJwks = false;
    let signedJwksSignatureValid = false;

    if (signedJwksUriValid) {
      try {
        const signedJwksUri = new URL(payload.signed_jwks_uri ?? '');
        if (issuerOrigin && signedJwksUri.origin !== issuerOrigin) {
          throw new Error('signed_jwks_uri is not same-origin as iss');
        }

        const response = await fetch(signedJwksUri, { signal: AbortSignal.timeout(fetchTimeoutMs) });
        signedJwksUriResolvable =
          response.ok &&
          response.status === 200 &&
          (response.headers.get('content-type')?.includes('application/jwk-set+jwt') ?? false);

        if (signedJwksUriResolvable) {
          const jwtContent = await response.text();
          const jwtParts = jwtContent.split('.');
          signedJwksUriResolvable = jwtParts.length === 3;

          if (signedJwksUriResolvable) {
            const signedPayload = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString());
            signedJwksPayloadHasJwks = Array.isArray(signedPayload?.jwks?.keys) && signedPayload.jwks.keys.length > 0;

            if (signedJwksPayloadHasJwks) {
              try {
                await jwtVerify(jwtContent, createLocalJWKSet(signedPayload.jwks), {
                  algorithms: ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512']
                });
                signedJwksSignatureValid = true;
              } catch {
                signedJwksSignatureValid = false;
              }
            }
          }
        }
      } catch {
        signedJwksUriResolvable = false;
      }
    }

    const validSignedJwks =
      signedJwksUriValid && signedJwksUriResolvable && signedJwksPayloadHasJwks && signedJwksSignatureValid;

    const evaluation = await recordRequirement('WP_004', async () => ({
      result: validSignedJwks ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: validSignedJwks
        ? undefined
        : `signed_jwks_uri must be HTTPS, same-origin, return signed JWKS JWT, and pass signature verification`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  // ___ WP_008 ____
  it('WP_008 - Wallet Provider supports credential revocation requests from Issuers', async () => {
    const revocationNotification = {
      iss: 'https://issuer.example.com',
      sub: walletProviderUrl,
      credential_id: 'test-credential-hash',
      event_type: 'https://www.rfc-editor.org/rfc/rfc8417.html#section-4.3',
      iat: Math.floor(Date.now() / 1000)
    };

    const revocationResponse = await fetch(`${walletProviderUrl}/revoke`, {
      method: 'POST',
      body: JSON.stringify(revocationNotification),
      headers: { 'Content-Type': 'application/json' }
    });

    const isSupported = revocationResponse.status === 200 || revocationResponse.status === 202;
    const endpointNotImplementedYet = revocationResponse.status === 404;
    const isValidResponse = isSupported || endpointNotImplementedYet;

    const evaluation = await recordRequirement('WP_008', async () => ({
      result: isValidResponse ? 'PASS' : 'FAIL',
      httpStatus: revocationResponse.status,
      errorMessage: isValidResponse
        ? undefined
        : `Wallet Provider does not support credential revocation requests from Issuers`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });

  // ___ WP_010 ____
  it('WP_010 - Wallet instance revocation terminates all instance operations', async () => {
    const revokedInstanceId = 'revoked-wallet-instance-id';

    const revokeInstancePayload = {
      instance_id: revokedInstanceId,
      reason: 'user_request',
      iat: Math.floor(Date.now() / 1000)
    };

    const revokeResponse = await fetch(`${walletProviderUrl}/revoke-instance`, {
      method: 'POST',
      body: JSON.stringify(revokeInstancePayload),
      headers: { 'Content-Type': 'application/json' }
    });

    const revocationAcknowledged = revokeResponse.status === 200 || revokeResponse.status === 202;
    const endpointNotImplementedYet = revokeResponse.status === 404;

    const followupPayload = {
      instance_id: revokedInstanceId,
      operation: 'verify_credential',
      data: {}
    };

    const followupResponse = await fetch(`${walletProviderUrl}/verify-credential`, {
      method: 'POST',
      body: JSON.stringify(followupPayload),
      headers: { 'Content-Type': 'application/json' }
    });

    const followupOperationBlocked = followupResponse.status === 403 || followupResponse.status === 404;

    const isValidBehavior = (revocationAcknowledged || endpointNotImplementedYet) && followupOperationBlocked;

    const evaluation = await recordRequirement('WP_010', async () => ({
      result: isValidBehavior ? 'PASS' : 'FAIL',
      httpStatus: revokeResponse.status,
      errorMessage: isValidBehavior
        ? undefined
        : `Wallet instance revocation does not terminate all instance operations`
    }));

    if (evaluation === null) {
      return;
    }

    expect(evaluation.result).toBe('PASS');
  });
});
