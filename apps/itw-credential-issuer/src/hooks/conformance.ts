import { extractIssuerSessionId, getRequirements } from '@itw-conformance-tool/conformance';
import fp from 'fastify-plugin';

import type { ConformanceStep } from '@itw-conformance-tool/conformance';
import type { FastifyInstance, FastifyRequest } from 'fastify';

type RequestConformanceCtx = {
  step: ConformanceStep;
  sessionId: string | null;
};

const STEP_MAP: Partial<Record<string, ConformanceStep>> = {
  'GET:/authorize': 'AUTHORIZE',
  'GET:/code/jwt': 'AUTHORIZATION_CODE',
  'POST:/as/par': 'PAR',
  'POST:/credential': 'CREDENTIAL',
  'POST:/nonce': 'NONCE',
  'POST:/presentation-response': 'PRESENTATION_RESPONSE',
  'POST:/token': 'TOKEN'
};

function resolveStep(method: string, routeUrl: string): ConformanceStep | undefined {
  return STEP_MAP[`${method}:${routeUrl}`];
}

function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function parseJsonPayload(payload: unknown): Record<string, unknown> | null {
  if (typeof payload === 'string') {
    try {
      return JSON.parse(payload) as Record<string, unknown>;
    } catch {
      return null;
    }
  }
  if (Buffer.isBuffer(payload)) {
    try {
      return JSON.parse(payload.toString('utf-8')) as Record<string, unknown>;
    } catch {
      return null;
    }
  }
  return null;
}

export default fp(
  async function conformanceHooks(app: FastifyInstance) {
    const repo = app.conformanceSessionRepository;

    // requestId → ctx: cleared in onResponse to avoid memory leaks
    const requestCtx = new Map<string, RequestConformanceCtx>();

    // jti → sessionId: populated after TOKEN success, consumed on CREDENTIAL lookup
    const tokenJtiMap = new Map<string, string>();

    // FIFO queue: sessionIds waiting for NONCE step correlation.
    // NONCE has no auth header so we correlate via the most-recently TOKEN-issued session.
    // This works correctly for sequential conformance tests; concurrent flows are not supported.
    const pendingNonceQueue: string[] = [];

    app.addHook('preHandler', async (request: FastifyRequest) => {
      const step = resolveStep(request.method, request.routeOptions.url ?? '');
      if (!step) return;

      if (step === 'PAR') {
        // Session is created from the PAR response body — sessionId unknown at request time
        requestCtx.set(request.id, { step, sessionId: null });
        return;
      }

      let sessionId: string | null = null;
      const query = request.query as Record<string, unknown>;

      if (step === 'AUTHORIZE' || step === 'PRESENTATION_RESPONSE' || step === 'AUTHORIZATION_CODE') {
        const requestUri = typeof query['request_uri'] === 'string' ? query['request_uri'] : null;
        if (requestUri) {
          sessionId = extractIssuerSessionId(requestUri);
        }
      } else if (step === 'TOKEN') {
        // Extract `code` from the parsed form body and resolve the matching PAR entry.
        // The preHandler runs before the route handler, so the code is still valid in the DB.
        const body = request.body;
        const code =
          body !== null && typeof body === 'object' && 'code' in body
            ? String((body as Record<string, unknown>)['code'])
            : null;

        if (code) {
          const row = app.dbClient.db
            .prepare(
              `SELECT request_uri FROM par_entries
               WHERE json_extract(request_object, '$.code') = ?
                 AND json_extract(request_object, '$.code_expires_at') >= unixepoch('now')
                 AND expires_at >= unixepoch('now') * 1000`
            )
            .get(code) as { request_uri: string } | undefined;

          if (row) {
            sessionId = extractIssuerSessionId(row.request_uri);
          }
        }
      } else if (step === 'NONCE') {
        // No auth header on this endpoint; correlate via FIFO queue populated at TOKEN success
        sessionId = pendingNonceQueue.shift() ?? null;
      } else if (step === 'CREDENTIAL') {
        // Correlate via Bearer token jti
        const auth = request.headers['authorization'];
        if (typeof auth === 'string' && auth.startsWith('Bearer ')) {
          const token = auth.slice(7);
          const payload = decodeJwtPayload(token);
          const jti = typeof payload?.['jti'] === 'string' ? payload['jti'] : null;
          if (jti) {
            sessionId = tokenJtiMap.get(jti) ?? null;
            if (sessionId) tokenJtiMap.delete(jti);
          }
        }
      }

      requestCtx.set(request.id, { step, sessionId });
    });

    app.addHook('onSend', async (request: FastifyRequest, reply, payload) => {
      const ctx = requestCtx.get(request.id);
      if (!ctx) return payload;

      const httpStatus = reply.statusCode;
      const isSuccess = httpStatus < 400;
      const timestamp = new Date().toISOString();
      const { step } = ctx;
      let { sessionId } = ctx;

      // PAR: create conformance session from the response body
      if (step === 'PAR' && isSuccess) {
        const body = parseJsonPayload(payload);
        const requestUri = typeof body?.['request_uri'] === 'string' ? body['request_uri'] : null;
        if (requestUri) {
          const sid = extractIssuerSessionId(requestUri);
          if (sid) {
            sessionId = sid;
            void repo
              .create({ sessionId: sid, startedAt: timestamp, status: 'OPEN', checks: [] })
              .catch(() => app.log.warn({ sessionId: sid }, 'Conformance: failed to create session'));
          }
        }
      }

      // TOKEN success: populate jti map and NONCE queue for downstream correlation.
      // Both must be populated together — if jti is absent we skip both so that NONCE
      // and CREDENTIAL remain in consistent state and the session is cleaned up by TTL.
      if (step === 'TOKEN' && isSuccess && sessionId) {
        const body = parseJsonPayload(payload);
        const accessToken = typeof body?.['access_token'] === 'string' ? body['access_token'] : null;
        if (accessToken) {
          const tokenPayload = decodeJwtPayload(accessToken);
          const jti = typeof tokenPayload?.['jti'] === 'string' ? tokenPayload['jti'] : null;
          if (jti) {
            tokenJtiMap.set(jti, sessionId);
            pendingNonceQueue.push(sessionId);
          }
        }
      }

      if (!sessionId) return payload;

      const requirements = getRequirements(step, 'ISSUANCE');
      const checkResult = isSuccess ? 'PASS' : ('FAIL' as const);

      for (const req of requirements) {
        void repo
          .appendCheck(sessionId, {
            description: req.description,
            errorMessage: isSuccess ? undefined : `HTTP ${httpStatus}`,
            httpStatus,
            phase: 'ISSUANCE',
            requirementId: req.requirementId,
            result: checkResult,
            step,
            timestamp
          })
          .catch(() => app.log.warn({ sessionId }, 'Conformance: failed to append check'));
      }

      // FR-3: close session on any 4xx/5xx, or on CREDENTIAL 2xx (PASSED)
      if (!isSuccess) {
        void repo
          .close(sessionId, 'FAILED')
          .catch(() => app.log.warn({ sessionId }, 'Conformance: failed to close session as FAILED'));
      } else if (step === 'CREDENTIAL') {
        void repo
          .close(sessionId, 'PASSED')
          .catch(() => app.log.warn({ sessionId }, 'Conformance: failed to close session as PASSED'));
      }

      return payload;
    });

    // onError catches errors thrown from route handlers (before serialization)
    app.addHook('onError', async (request: FastifyRequest, reply, error) => {
      const ctx = requestCtx.get(request.id);
      if (!ctx?.sessionId) return;

      const { step, sessionId } = ctx;
      const timestamp = new Date().toISOString();
      const httpStatus = reply.statusCode || 500;
      const requirements = getRequirements(step, 'ISSUANCE');

      for (const req of requirements) {
        void repo
          .appendCheck(sessionId, {
            description: req.description,
            errorMessage: error.message,
            httpStatus,
            phase: 'ISSUANCE',
            requirementId: req.requirementId,
            result: 'FAIL',
            step,
            timestamp
          })
          .catch((_err: unknown) => {
            // silently swallow — conformance errors must not affect the response
          });
      }

      void repo.close(sessionId, 'FAILED').catch((_err: unknown) => {
        // silently swallow — conformance errors must not affect the response
      });
    });

    // Always clean up per-request state to prevent memory leaks
    app.addHook('onResponse', async (request: FastifyRequest) => {
      requestCtx.delete(request.id);
    });
  },
  { dependencies: ['db'], name: 'conformanceHooks' }
);
