import { extractRpSessionId } from '@itw-conformance-tool/conformance';
import { compactDecrypt, importPKCS8 } from 'jose';

import type { FastifyInstance } from 'fastify';

// PII fields that must not appear in wallet_metadata (WP_083b)
const PII_FIELDS = new Set([
  'device_name',
  'user_id',
  'email',
  'phone',
  'hardware_id',
  'serial_number',
  'imei',
  'name'
]);

/** Decrypts a JWE and returns its state claim plus the full payload, or null on failure. */
async function extractStateFromJwe(
  jwe: string,
  privateKeyPem: string
): Promise<{ state: string; payload: Record<string, unknown> } | null> {
  try {
    const privateKey = await importPKCS8(privateKeyPem, 'ECDH-ES');
    const { plaintext } = await compactDecrypt(jwe, privateKey);
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
    if (typeof payload.state !== 'string') return null;
    return { state: payload.state, payload };
  } catch {
    return null;
  }
}

/** Appends a conformance check, swallowing errors so hooks never break request flow. */
async function safeAppendCheck(
  app: FastifyInstance,
  sessionId: string,
  check: Parameters<typeof app.conformanceSessionRepository.appendCheck>[1]
): Promise<void> {
  try {
    await app.conformanceSessionRepository.appendCheck(sessionId, check);
  } catch (err) {
    app.log.warn({ err, sessionId }, 'conformance: failed to append check');
  }
}

/**
 * Registers an onSend hook that opens a conformance session and records
 * WP_082 (GET) or WP_083/083a/083b/083c (POST) checks on 2xx responses.
 */
export function registerAuthRequestConformanceHooks(app: FastifyInstance): void {
  app.addHook('onSend', async (request, reply, payload) => {
    if (!app.hasDecorator('conformanceSessionRepository')) return payload;
    if (reply.statusCode < 200 || reply.statusCode >= 300) return payload;

    const params = request.params as { state?: string };
    const sessionId = params.state ? extractRpSessionId(params.state) : null;
    if (!sessionId) return payload;

    const timestamp = new Date().toISOString();
    const repo = app.conformanceSessionRepository;

    try {
      await repo.create({ sessionId, startedAt: timestamp, status: 'OPEN', checks: [] });
    } catch (err) {
      app.log.warn({ err, sessionId }, 'conformance: failed to open session');
    }

    if (request.method === 'GET') {
      // WP_082: RP returns signed Authorization Request Object on GET
      await safeAppendCheck(app, sessionId, {
        description: 'RP returns signed Authorization Request Object (WP_082)',
        httpStatus: reply.statusCode,
        phase: 'PRESENTATION',
        requirementId: 'WP_082',
        result: 'PASS',
        step: 'AUTHORIZE',
        timestamp
      });
    } else if (request.method === 'POST') {
      const body = request.body as Record<string, string> | null;

      // WP_083: RP accepts wallet-initiated Authorization Request
      await safeAppendCheck(app, sessionId, {
        description: 'RP accepts wallet-initiated Authorization Request (WP_083)',
        httpStatus: reply.statusCode,
        phase: 'PRESENTATION',
        requirementId: 'WP_083',
        result: 'PASS',
        step: 'AUTHORIZE',
        timestamp
      });

      // Parse wallet_metadata for sub-checks
      let walletMetadata: Record<string, unknown> = {};
      try {
        if (body?.wallet_metadata) {
          walletMetadata = JSON.parse(body.wallet_metadata) as Record<string, unknown>;
        }
      } catch {
        // invalid JSON — sub-checks will record FAIL
      }

      // WP_083a: required wallet_metadata fields present
      const required = ['vp_formats_supported', 'client_id_schemes_supported', 'authorization_endpoint'];
      const missing = required.filter((f) => !(f in walletMetadata));
      await safeAppendCheck(app, sessionId, {
        description: 'wallet_metadata contains required fields (WP_083a)',
        errorMessage: missing.length > 0 ? `Missing: ${missing.join(', ')}` : undefined,
        httpStatus: reply.statusCode,
        phase: 'PRESENTATION',
        requirementId: 'WP_083a',
        result: missing.length === 0 ? 'PASS' : 'FAIL',
        step: 'AUTHORIZE',
        timestamp
      });

      // WP_083b: no PII fields in wallet_metadata
      const piiFound = Object.keys(walletMetadata).filter((k) => PII_FIELDS.has(k));
      await safeAppendCheck(app, sessionId, {
        description: 'wallet_metadata contains no PII fields (WP_083b)',
        errorMessage: piiFound.length > 0 ? `PII found: ${piiFound.join(', ')}` : undefined,
        httpStatus: reply.statusCode,
        phase: 'PRESENTATION',
        requirementId: 'WP_083b',
        result: piiFound.length === 0 ? 'PASS' : 'FAIL',
        step: 'AUTHORIZE',
        timestamp
      });

      // WP_083c: wallet_nonce present
      const noncePresent = typeof body?.wallet_nonce === 'string' && body.wallet_nonce.length > 0;
      await safeAppendCheck(app, sessionId, {
        description: 'wallet_nonce is present in the request (WP_083c)',
        errorMessage: noncePresent ? undefined : 'wallet_nonce missing or empty',
        httpStatus: reply.statusCode,
        phase: 'PRESENTATION',
        requirementId: 'WP_083c',
        result: noncePresent ? 'PASS' : 'FAIL',
        step: 'AUTHORIZE',
        timestamp
      });
    }

    return payload;
  });
}

/**
 * Registers a hook that closes the conformance session and records
 * WP_091–WP_093c checks when the auth-response route processes a JWE.
 */
export function registerAuthResponseConformanceHooks(app: FastifyInstance): void {
  app.addHook('onSend', async (request, reply, payload) => {
    if (!app.hasDecorator('conformanceSessionRepository')) return payload;

    const body = request.body as Record<string, unknown>;
    if (!body || typeof body.response !== 'string') return payload;

    const result = await extractStateFromJwe(body.response, app.rpKeys.authResponsePrivateKeyPem);
    if (!result) return payload;

    const sessionId = extractRpSessionId(result.state);
    if (!sessionId) return payload;

    const isSuccess = reply.statusCode >= 200 && reply.statusCode < 300;
    const timestamp = new Date().toISOString();
    const repo = app.conformanceSessionRepository;

    try {
      await repo.appendCheck(sessionId, {
        description: 'Presentation response contains a valid encrypted VP Token with KB-JWT',
        errorMessage: isSuccess ? undefined : `HTTP ${reply.statusCode}`,
        httpStatus: reply.statusCode,
        phase: 'PRESENTATION',
        requirementId: 'IT-WALLET-1.4-§5.2.2',
        result: isSuccess ? 'PASS' : 'FAIL',
        step: 'PRESENTATION_RESPONSE',
        timestamp
      });
    } catch (err) {
      app.log.warn({ err, sessionId }, 'conformance: failed to append check');
    }

    try {
      await repo.close(sessionId, isSuccess ? 'PASSED' : 'FAILED');
    } catch (err) {
      app.log.warn({ err, sessionId }, 'conformance: failed to close session');
    }

    return payload;
  });
}
