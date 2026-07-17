import { extractRpSessionId } from '@itw-conformance-tool/conformance';
import type { ClosedConformanceSessionStatus } from '@itw-conformance-tool/conformance';
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

    try {
      await app.conformanceSessionRepository.create({
        sessionId,
        startedAt: new Date().toISOString(),
        status: 'OPEN',
        checks: []
      });
    } catch (err) {
      app.log.warn({ err, sessionId }, 'conformance: failed to open session');
    }

    return payload;
  });
}

/** Registers a hook that automatically closes the conformance session
 * when the route receives a presentation response.
 *
 * Closes as PASSED on 2xx (JWE or OAuth error correctly sent by the Wallet)
 * and as FAILED on non-2xx (RP rejected the request), so the session is
 * never left permanently OPEN on failures or timeouts.
 *
 * @param app Fastify instance to register the hook on
 * @returns void
 */
export function registerAuthResponseConformanceHooks(app: FastifyInstance): void {
  app.addHook('onSend', async (request, reply, payload) => {
    if (!app.hasDecorator('conformanceSessionRepository')) return payload;

    const body = request.body as Record<string, unknown>;
    if (!body) return payload;

    let sessionId: string | null = null;
    let closeStatus: ClosedConformanceSessionStatus;

    if (typeof body.response === 'string') {
      // JARM JWE: { response: "<JWE>" } — result depends on RP HTTP status
      const state = await extractStateFromJwe(body.response, app.rpKeys.authResponsePrivateKeyPem);
      sessionId = state ? extractRpSessionId(state) : null;
      closeStatus = reply.statusCode >= 200 && reply.statusCode < 300 ? 'PASSED' : 'FAILED';
    } else if (typeof body.state === 'string') {
      // OAuth error from Wallet: { error: "...", state: "<uuid>" } — always FAILED
      sessionId = extractRpSessionId(body.state);
      closeStatus = 'FAILED';
    } else {
      return payload;
    }

    if (!sessionId) return payload;

    try {
      await app.conformanceSessionRepository.close(sessionId, closeStatus);
    } catch (err) {
      app.log.warn({ err, sessionId }, 'conformance: failed to close session');
    }

    return payload;
  });
}
