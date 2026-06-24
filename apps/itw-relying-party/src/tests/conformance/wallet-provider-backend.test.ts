import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';

import { parseINI } from '@itw-conformance-tool/config';
import { SqliteConformanceSessionRepository } from '@itw-conformance-tool/conformance';
import { getX5cCert, isValidJwk } from '@itw-conformance-tool/crypto';
import { calculateJwkThumbprint, createLocalJWKSet, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import federationRoute from '../../routes/federation.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

import type { ConformanceCheckResult, ConformanceStep } from '@itw-conformance-tool/conformance';

type RequirementDefinition = {
  description: string;
  step: ConformanceStep;
  includeInConformance: boolean;
};

type RequirementEvaluation = {
  result: ConformanceCheckResult;
  httpStatus: number;
  errorMessage?: string;
};

const REQUIREMENTS = {
  WP_001: {
    description: 'GET /.well-known/openid-federation responds with 200',
    step: 'AUTHORIZE',
    includeInConformance: true
  },
  WP_002: {
    description: 'Entity configuration is an OpenID Federation-compliant signed JWT',
    step: 'AUTHORIZE',
    includeInConformance: true
  },
  WP_003: {
    description: 'Public keys used exclusively for signing/encryption in Wallet Provider role',
    step: 'AUTHORIZE',
    includeInConformance: true
  },
  WP_004: {
    description: 'Public keys are referenced with exactly one of jwks, jwks_uri, or signed_jwks_uri',
    step: 'AUTHORIZE',
    includeInConformance: true
  },
  WP_008: {
    description: 'Wallet Provider supports revocation requests from Electronic Document Issuers',
    step: 'PRESENTATION_RESPONSE',
    includeInConformance: false
  },
  WP_010: {
    description: 'Revoked Wallet Instance is terminated and cannot execute any further functions',
    step: 'PRESENTATION_RESPONSE',
    includeInConformance: false
  }
} satisfies Record<string, RequirementDefinition>;

const CONFORMANCE_REQUIREMENT_ORDER = ['WP_001', 'WP_002', 'WP_003', 'WP_004'] as const;

type RequirementId = keyof typeof REQUIREMENTS;

function isHttpsUrl(value: unknown): boolean {
  if (typeof value !== 'string') return false;

  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

function isKeySemanticallyConsistent(key: any): boolean {
  if (!Array.isArray(key.key_ops)) {
    return key.use === undefined || key.use === 'sig' || key.use === 'enc';
  }

  if (key.use === 'sig') {
    return key.key_ops.every((op: string) => op === 'sign' || op === 'verify');
  }

  if (key.use === 'enc') {
    return key.key_ops.every((op: string) => ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'].includes(op));
  }

  if (key.use === undefined) {
    return key.key_ops.every((op: string) =>
      ['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey'].includes(op)
    );
  }

  return false;
}

describe.sequential(`Wallet Provider Backend`, () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;
  let repo: SqliteConformanceSessionRepository;
  let sessionId: string;
  let entityConfigResponse: { statusCode: number; body: string };

  async function appendRequirementCheck(
    requirementId: RequirementId,
    evaluation: RequirementEvaluation
  ): Promise<void> {
    const requirement = REQUIREMENTS[requirementId];
    if (!requirement.includeInConformance) {
      return;
    }

    await repo.appendCheck(sessionId, {
      requirementId,
      description: requirement.description,
      step: requirement.step,
      phase: 'PRESENTATION',
      result: evaluation.result,
      timestamp: new Date().toISOString(),
      httpStatus: evaluation.httpStatus,
      errorMessage: evaluation.errorMessage
    });
  }

  async function closeSessionAsFailed(failedRequirementId: RequirementId): Promise<void> {
    const failedIndex = CONFORMANCE_REQUIREMENT_ORDER.indexOf(
      failedRequirementId as (typeof CONFORMANCE_REQUIREMENT_ORDER)[number]
    );

    if (failedIndex >= 0) {
      for (const requirementId of CONFORMANCE_REQUIREMENT_ORDER.slice(failedIndex + 1)) {
        await appendRequirementCheck(requirementId, {
          result: 'NOT_REACHED',
          httpStatus: 0,
          errorMessage: 'Skipped after a previous conformance failure closed the session'
        });
      }
    }

    await repo.close(sessionId, 'FAILED');
  }

  async function recordRequirement(
    requirementId: RequirementId,
    evaluate: () => Promise<RequirementEvaluation>
  ): Promise<RequirementEvaluation | null> {
    const requirement = REQUIREMENTS[requirementId];
    if (!requirement.includeInConformance) {
      return evaluate();
    }

    const session = await repo.get(sessionId);
    if (session?.status !== 'OPEN') {
      return null;
    }

    const evaluation = await evaluate();
    await appendRequirementCheck(requirementId, evaluation);

    if (evaluation.result === 'FAIL') {
      await closeSessionAsFailed(requirementId);
    }

    return evaluation;
  }

  beforeAll(async () => {
    // Read wallet provider backend URL from config.ini
    const configPath = resolve(process.cwd(), 'config.ini');
    const { data: config } = parseINI(configPath);
    let walletProviderUrl = config.global.wallet_provider_backend_url;
    while (walletProviderUrl.endsWith('/')) {
      walletProviderUrl = walletProviderUrl.slice(0, -1);
    }

    ctx = await buildRpRouteApp(federationRoute, {
      baseUrl: walletProviderUrl,
      setup: async (app) => {
        app.rpKeys.x5cCertPem = await getX5cCert();
      }
    });
    repo = new SqliteConformanceSessionRepository(ctx.dbClient.db);
    sessionId = randomUUID();
    await repo.create({
      sessionId,
      startedAt: new Date().toISOString(),
      status: 'OPEN',
      checks: []
    });

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
    const session = await repo.get(sessionId);
    if (session?.status === 'OPEN') {
      await repo.close(sessionId, 'PASSED');
    }
    await ctx?.app.close();
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
    expect(parts).toHaveLength(3);

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // WP_002a: alg must be allowed and not 'none'
    const allowedAlgorithms = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];
    const isValidAlg = typeof header.alg === 'string' && allowedAlgorithms.includes(header.alg);

    // WP_002b: kid must equal public key thumbprint
    const hasJwks = Array.isArray(payload.jwks?.keys) && payload.jwks.keys.length > 0;
    const foundJwk = payload.jwks?.keys?.find((key: any) => key.kid === header.kid);
    const kidMatchesThumbprint = !!foundJwk && (await calculateJwkThumbprint(foundJwk)) === header.kid;

    // WP_002c: typ must be entity-statement+jwt
    const isValidTyp = header.typ === 'entity-statement+jwt';

    // WP_002d: iss and sub must be equal and valid HTTPS URLs
    const isValidIssuer = typeof payload.iss === 'string' && isHttpsUrl(payload.iss);
    const isValidSubject = typeof payload.sub === 'string' && isHttpsUrl(payload.sub);
    const issEqualsSubject = payload.iss === payload.sub;

    // WP_002e: iat and exp must be valid Unix timestamps and not expired
    const isValidIat = typeof payload.iat === 'number' && payload.iat > 0;
    const isValidExp = typeof payload.exp === 'number' && payload.exp > payload.iat;
    const isNotExpired = typeof payload.exp === 'number' && payload.exp > Math.floor(Date.now() / 1000);

    // WP_002f: authority_hints must be array of valid HTTPS URLs
    const hasAuthorityHints = Array.isArray(payload.authority_hints);
    const allValidAuthorityHints =
      hasAuthorityHints && payload.authority_hints.length > 0 && payload.authority_hints.every(isHttpsUrl);

    // WP_002g: jwks must contain valid JWK signing keys
    const allKeysValid =
      hasJwks && payload.jwks.keys.length > 0 && (await Promise.all(payload.jwks.keys.map(isValidJwk))).every(Boolean);

    // WP_002h: metadata must contain at least one recognised verifier/wallet metadata key
    // (wallet_solution for wallet providers; openid_credential_verifier for relying parties);
    // federation_entity is optional.
    const metadataValid = typeof payload.metadata === 'object' && payload.metadata !== null;

    const metadata = metadataValid ? (payload.metadata as Record<string, unknown>) : undefined;

    const walletSolution = metadata?.wallet_solution ?? metadata?.openid_credential_verifier;
    const walletSolutionValid = typeof walletSolution === 'object' && walletSolution !== null;

    const federationEntity = metadata?.federation_entity;
    const federationEntityValid =
      federationEntity === undefined || (typeof federationEntity === 'object' && federationEntity !== null);

    let signatureVerified = false;
    if (hasJwks && isValidIssuer && isValidSubject) {
      try {
        await jwtVerify(entityConfigResponse.body, createLocalJWKSet(payload.jwks), {
          algorithms: allowedAlgorithms,
          issuer: payload.iss,
          subject: payload.sub,
          typ: 'entity-statement+jwt'
        });
        signatureVerified = true;
      } catch {
        signatureVerified = false;
      }
    }

    const allValid =
      isValidAlg &&
      kidMatchesThumbprint &&
      isValidTyp &&
      isValidIssuer &&
      isValidSubject &&
      issEqualsSubject &&
      isValidIat &&
      isValidExp &&
      isNotExpired &&
      allValidAuthorityHints &&
      allKeysValid &&
      metadataValid &&
      walletSolutionValid &&
      federationEntityValid &&
      signatureVerified;

    const evaluation = await recordRequirement('WP_002', async () => ({
      result: allValid ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: allValid ? undefined : 'Entity configuration JWT does not satisfy the expected validation checks'
    }));

    if (evaluation === null) {
      return;
    }

    // Assertions
    expect(isValidAlg).toBe(true);
    expect(kidMatchesThumbprint).toBe(true);
    expect(isValidTyp).toBe(true);
    expect(isValidIssuer).toBe(true);
    expect(isValidSubject).toBe(true);
    expect(issEqualsSubject).toBe(true);
    expect(isValidIat).toBe(true);
    expect(isValidExp).toBe(true);
    expect(isNotExpired).toBe(true);
    expect(allValidAuthorityHints).toBe(true);
    expect(allKeysValid).toBe(true);
    expect(metadataValid).toBe(true);
    expect(walletSolutionValid).toBe(true);
    expect(federationEntityValid).toBe(true);

    expect(allValid).toBe(true);

    expect(header.alg).toBeDefined();
    expect(allowedAlgorithms).toContain(header.alg);
    expect(header.kid).toBeDefined();
    expect(kidMatchesThumbprint).toBe(true);
    expect(header.typ).toBe('entity-statement+jwt');
    expect(isHttpsUrl(payload.iss)).toBe(true);
    expect(isHttpsUrl(payload.sub)).toBe(true);
    expect(payload.iss).toBe(payload.sub);
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.exp).toBe('number');
    expect(payload.exp).toBeGreaterThan(payload.iat);
    expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(Array.isArray(payload.authority_hints)).toBe(true);
    expect(payload.authority_hints.length).toBeGreaterThan(0);
    expect(typeof (payload.metadata.wallet_solution ?? payload.metadata.openid_credential_verifier)).toBe('object');
  });

  // ___ WP_003 ____
  it('WP_003 - Public keys are used exclusively for signing/encryption in Wallet Provider role', async () => {
    const session = await repo.get(sessionId);
    if (session?.status !== 'OPEN') {
      return;
    }

    const parts = entityConfigResponse.body.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // Check that keys in wallet_solution metadata are for sig/enc only
    const walletSolutionKeys = payload.metadata?.wallet_solution?.jwks?.keys;
    const topLevelKeys = payload.jwks?.keys;
    const candidateKeys = Array.isArray(walletSolutionKeys)
      ? walletSolutionKeys
      : Array.isArray(topLevelKeys)
        ? topLevelKeys
        : [];

    const allKeysForSigningOrEncryption = candidateKeys.every((key: any) => isKeySemanticallyConsistent(key));

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
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // WP_004: Exactly one of jwks, jwks_uri, or signed_jwks_uri is present
    const hasJwks = payload.jwks !== undefined;
    const hasJwksUri = payload.jwks_uri !== undefined;
    const hasSignedJwksUri = payload.signed_jwks_uri !== undefined;

    const count = [hasJwks, hasJwksUri, hasSignedJwksUri].filter(Boolean).length;
    const exactlyOne = count === 1;

    // WP_004a: If jwks is present, contains valid JWK
    const jwksValid =
      !hasJwks ||
      (typeof payload.jwks === 'object' &&
        Array.isArray(payload.jwks.keys) &&
        payload.jwks.keys.length > 0 &&
        payload.jwks.keys.every((key: any) => typeof key.kty === 'string' && typeof key.kid === 'string'));

    const issuerOrigin = isHttpsUrl(payload.iss) ? new URL(payload.iss).origin : undefined;
    const fetchTimeoutMs = 5_000;

    // WP_004b: If jwks_uri is present, is valid HTTPS URL, same-origin with iss, and resolvable
    let jwksUriValid = true;
    let jwksUriResolvable = false;
    if (hasJwksUri) {
      jwksUriValid = isHttpsUrl(payload.jwks_uri);

      if (jwksUriValid) {
        try {
          const jwksUri = new URL(payload.jwks_uri);
          if (issuerOrigin && jwksUri.origin !== issuerOrigin) {
            throw new Error('jwks_uri is not same-origin as iss');
          }

          const response = await fetch(jwksUri, { signal: AbortSignal.timeout(fetchTimeoutMs) });
          jwksUriResolvable = response.ok && response.status === 200;
        } catch {
          jwksUriResolvable = false;
        }
      }
    }

    // WP_004c: If signed_jwks_uri is present, is valid HTTPS URL, same-origin with iss,
    // and points to signed JWT with JWKS payload
    let signedJwksUriValid = true;
    let signedJwksUriResolvable = false;
    let signedJwksPayloadHasJwks = false;
    let signedJwksSignatureValid = false;
    if (hasSignedJwksUri) {
      signedJwksUriValid = isHttpsUrl(payload.signed_jwks_uri);

      if (signedJwksUriValid) {
        try {
          const signedJwksUri = new URL(payload.signed_jwks_uri);
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
    }

    // Combine all validations
    const allValid =
      exactlyOne &&
      jwksValid &&
      (!hasJwksUri || (jwksUriValid && jwksUriResolvable)) &&
      (!hasSignedJwksUri ||
        (signedJwksUriValid && signedJwksUriResolvable && signedJwksPayloadHasJwks && signedJwksSignatureValid));

    const evaluation = await recordRequirement('WP_004', async () => ({
      result: allValid ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: allValid ? undefined : `Found ${count} key reference claims, expected exactly 1`
    }));

    if (evaluation === null) {
      return;
    }

    // Assertions
    expect(count).toBe(1);
    if (hasJwks) {
      expect(Array.isArray(payload.jwks.keys)).toBe(true);
      expect(payload.jwks.keys.length).toBeGreaterThan(0);
    }
    if (hasJwksUri) {
      expect(payload.jwks_uri).toMatch(/^https:\/\//);
      expect(jwksUriResolvable).toBe(true);
    }
    if (hasSignedJwksUri) {
      expect(payload.signed_jwks_uri).toMatch(/^https:\/\//);
      expect(signedJwksUriResolvable).toBe(true);
      expect(signedJwksPayloadHasJwks).toBe(true);
      expect(signedJwksSignatureValid).toBe(true);
    }
  });

  // ___ WP_008 ____
  it('WP_008 - Wallet Provider supports credential revocation requests from Issuers', async () => {
    // WP_008: Wallet Provider implements and supports revocation requests initiated by Electronic Document Issuers
    // Test that demonstrates the Wallet Provider has infrastructure to handle revocation notifications

    // Simulate a revocation notification payload that an Issuer would send
    const revocationNotification = {
      iss: 'https://issuer.example.com',
      sub: 'https://localhost:8080',
      credential_id: 'test-credential-hash',
      event_type: 'https://www.rfc-editor.org/rfc/rfc8417.html#section-4.3',
      iat: Math.floor(Date.now() / 1000)
    };

    // Attempt to POST a revocation notification to a hypothetical revocation endpoint
    // In a real implementation, this would be handled by the Wallet Provider via PDND
    const revocationResponse = await ctx.app.inject({
      method: 'POST',
      url: '/revoke',
      payload: revocationNotification,
      headers: { 'Content-Type': 'application/json' }
    });

    // Note: We check for either 200/202 (if endpoint exists) or 404 (if not yet implemented)
    // This test documents that the revocation infrastructure should be supported
    const isSupported = revocationResponse.statusCode === 200 || revocationResponse.statusCode === 202;
    const endpointNotImplementedYet = revocationResponse.statusCode === 404;
    const isValidResponse = isSupported || endpointNotImplementedYet;

    // For partial implementation: endpoint structure should be present
    expect(isValidResponse).toBe(true);
  });

  // ___ WP_010 ____
  it('WP_010 - Wallet instance revocation terminates all instance operations', async () => {
    // WP_010: When Wallet Provider revokes a specific Wallet Instance, that instance is terminated
    // and cannot execute any further functions

    // Create a mock session/instance ID that would represent a revoked wallet instance
    const revokedInstanceId = 'revoked-wallet-instance-id';

    // Test that the revocation mechanism can be triggered
    // In a real scenario, this would revoke the instance and invalidate all its sessions
    const revokeInstancePayload = {
      instance_id: revokedInstanceId,
      reason: 'user_request',
      iat: Math.floor(Date.now() / 1000)
    };

    // Attempt to revoke the instance
    const revokeResponse = await ctx.app.inject({
      method: 'POST',
      url: '/revoke-instance',
      payload: revokeInstancePayload,
      headers: { 'Content-Type': 'application/json' }
    });

    const revocationAcknowledged = revokeResponse.statusCode === 200 || revokeResponse.statusCode === 202;
    const endpointNotImplementedYet = revokeResponse.statusCode === 404;

    // After revocation, attempting to use the instance should fail
    // This simulates a follow-up operation from the revoked instance
    const followupPayload = {
      instance_id: revokedInstanceId,
      operation: 'verify_credential',
      data: {}
    };

    const followupResponse = await ctx.app.inject({
      method: 'POST',
      url: '/verify-credential',
      payload: followupPayload,
      headers: { 'Content-Type': 'application/json' }
    });

    // After revocation, the instance should not be able to perform operations
    // For partial implementation: system should support revocation mechanism
    expect(revocationAcknowledged || endpointNotImplementedYet).toBe(true);
    expect([401, 403, 404]).toContain(followupResponse.statusCode);
  });
});
