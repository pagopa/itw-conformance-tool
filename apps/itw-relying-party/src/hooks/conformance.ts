import { extractRpSessionId, getRequirements } from '@itw-conformance-tool/conformance';
import { compactDecrypt, importPKCS8 } from 'jose';

import type { FastifyInstance } from 'fastify';

/** Extracts the `state` claim from the decrypted JWE payload.
 *
 * @param jwe The JWE string to decrypt
 * @param privateKeyPem The PEM-encoded private key to use for decryption
 * @returns The `state` claim if present, otherwise `null`
 */
async function extractStateFromJwe(jwe: string, privateKeyPem: string): Promise<string | null> {
  try {
    const privateKey = await importPKCS8(privateKeyPem, 'ECDH-ES');
    const { plaintext } = await compactDecrypt(jwe, privateKey);
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
    return typeof payload.state === 'string' ? payload.state : null;
  } catch {
    return null;
  }
}

/** Registers an onSend hook that automatically opens a conformance
 * session when the route returns a successful (2xx) response.
 *
 * @param app Fastify instance to register the hook on
 * @returns void
 */
export function registerAuthRequestConformanceHooks(app: FastifyInstance): void {
  app.addHook('onSend', async (_request, reply, payload) => {
    if (!app.hasDecorator('conformanceSessionRepository')) return payload;
    if (reply.statusCode < 200 || reply.statusCode >= 300) return payload;

    const params = _request.params as { state?: string };
    const sessionId = params.state ? extractRpSessionId(params.state) : null;
    if (!sessionId) return payload;

    const timestamp = new Date().toISOString();
    const repo = app.conformanceSessionRepository;

    try {
      await repo.create({
        sessionId,
        startedAt: timestamp,
        status: 'OPEN',
        checks: []
      });
    } catch (err) {
      app.log.warn({ err, sessionId }, 'conformance: failed to open session');
    }

    const requirements = getRequirements('AUTHORIZE', 'PRESENTATION');
    for (const req of requirements) {
      try {
        await repo.appendCheck(sessionId, {
          description: req.description,
          httpStatus: reply.statusCode,
          phase: 'PRESENTATION',
          requirementId: req.requirementId,
          result: 'PASS',
          step: 'AUTHORIZE',
          timestamp
        });
      } catch (err) {
        app.log.warn({ err, sessionId }, 'conformance: failed to append check');
      }
    }

    return payload;
  });
}

/** Registers a hook that automatically closes the conformance session
 * as PASSED when the route returns a successful response containing
 * a verified presentation.
 *
 * @param app Fastify instance to register the hook on
 * @returns void
 */
export function registerAuthResponseConformanceHooks(app: FastifyInstance): void {
  app.addHook('onSend', async (request, reply, payload) => {
    if (!app.hasDecorator('conformanceSessionRepository')) return payload;

    const body = request.body as Record<string, unknown>;
    if (!body || typeof body.response !== 'string') return payload;

    const state = await extractStateFromJwe(body.response, app.rpKeys.authResponsePrivateKeyPem);
    if (!state) return payload;

    const sessionId = extractRpSessionId(state);
    if (!sessionId) return payload;

    const isSuccess = reply.statusCode >= 200 && reply.statusCode < 300;
    const timestamp = new Date().toISOString();
    const repo = app.conformanceSessionRepository;

    const requirements = getRequirements('PRESENTATION_RESPONSE', 'PRESENTATION');
    const checkResult = isSuccess ? 'PASS' : 'FAIL';

    for (const req of requirements) {
      try {
        await repo.appendCheck(sessionId, {
          description: req.description,
          errorMessage: isSuccess ? undefined : `HTTP ${reply.statusCode}`,
          httpStatus: reply.statusCode,
          phase: 'PRESENTATION',
          requirementId: req.requirementId,
          result: checkResult,
          step: 'PRESENTATION_RESPONSE',
          timestamp
        });
      } catch (err) {
        app.log.warn({ err, sessionId }, 'conformance: failed to append check');
      }
    }

    try {
      await repo.close(sessionId, isSuccess ? 'PASSED' : 'FAILED');
    } catch (err) {
      app.log.warn({ err, sessionId }, 'conformance: failed to close session');
    }

    return payload;
  });
}
