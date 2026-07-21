import {
  createConformanceInstrumentationPlugin,
  extractIssuerSessionId,
  type ConformanceStep,
  type ScenarioCorrelation
} from '@itw-conformance-tool/conformance';
import fp from 'fastify-plugin';
import { decodeJwt } from 'jose';

import type { FastifyInstance, FastifyRequest } from 'fastify';

const STEP_MAP: Partial<Record<string, ConformanceStep>> = {
  'GET:/authorize': 'AUTHORIZE',
  'GET:/code/jwt': 'AUTHORIZATION_CODE',
  'POST:/as/par': 'PAR',
  'POST:/credential': 'CREDENTIAL',
  'POST:/nonce': 'NONCE',
  'POST:/presentation-response': 'PRESENTATION_RESPONSE',
  'POST:/token': 'TOKEN'
};

type ExpiringCorrelation = ScenarioCorrelation & {
  expiresAt: number;
};

type CorrelationState = {
  pendingNonce: ExpiringCorrelation[];
  tokenJti: Map<string, ExpiringCorrelation>;
};

function resolveStep(request: FastifyRequest): ConformanceStep | undefined {
  return STEP_MAP[`${request.method}:${request.routeOptions.url ?? ''}`];
}

function toCorrelation(correlationId: string | null): ScenarioCorrelation | null {
  return correlationId ? { correlationId, scenarioId: correlationId } : null;
}

function getRequestUriCorrelation(request: FastifyRequest): ScenarioCorrelation | null {
  const query = request.query as Record<string, unknown>;
  const requestUri = typeof query['request_uri'] === 'string' ? query['request_uri'] : null;
  return toCorrelation(requestUri ? extractIssuerSessionId(requestUri) : null);
}

function getTokenRequestCode(body: unknown): string | null {
  if (body !== null && typeof body === 'object' && 'code' in body) {
    const code = (body as Record<string, unknown>)['code'];
    return typeof code === 'string' && code.length > 0 ? code : null;
  }

  if (typeof body === 'string') {
    return new URLSearchParams(body).get('code');
  }

  return null;
}

function getAccessToken(request: FastifyRequest): string | null {
  const authorization = request.headers.authorization;
  if (typeof authorization !== 'string') return null;

  const [scheme, token, ...rest] = authorization.trim().split(/\s+/);
  return rest.length === 0 && scheme?.toLowerCase() === 'dpop' && token ? token : null;
}

function removeExpiredCorrelations(state: CorrelationState, now = Date.now()): void {
  for (const [jti, correlation] of state.tokenJti) {
    if (correlation.expiresAt <= now) {
      state.tokenJti.delete(jti);
    }
  }

  state.pendingNonce = state.pendingNonce.filter((correlation) => correlation.expiresAt > now);
}

function resolveCorrelation(
  request: FastifyRequest,
  app: FastifyInstance,
  state: CorrelationState
): ScenarioCorrelation | null {
  removeExpiredCorrelations(state);

  const step = resolveStep(request);
  if (!step || step === 'PAR') return null;

  if (step === 'AUTHORIZE' || step === 'PRESENTATION_RESPONSE' || step === 'AUTHORIZATION_CODE') {
    return getRequestUriCorrelation(request);
  }

  if (step === 'TOKEN') {
    const code = getTokenRequestCode(request.body);
    if (!code) return null;

    const row = app.dbClient.get<{ request_uri: string }>(
      `SELECT request_uri FROM par_entries
       WHERE json_extract(request_object, '$.code') = ?
         AND json_extract(request_object, '$.code_expires_at') >= unixepoch('now')
         AND expires_at >= unixepoch('now') * 1000`,
      [code]
    );

    return toCorrelation(row ? extractIssuerSessionId(row.request_uri) : null);
  }

  if (step === 'NONCE') {
    // The nonce endpoint carries no flow identifier. FIFO is the only possible
    // fallback, while request_uri and token jti keep every other step deterministic.
    const pending = state.pendingNonce.shift();
    return pending ? toCorrelation(pending.correlationId) : null;
  }

  const accessToken = getAccessToken(request);
  if (!accessToken) return null;

  const payload = decodeJwt(accessToken);
  const jti = typeof payload.jti === 'string' ? payload.jti : null;
  if (!jti) return null;

  const correlation = state.tokenJti.get(jti);
  if (!correlation) return null;
  if (correlation.expiresAt <= Date.now()) {
    state.tokenJti.delete(jti);
    return null;
  }

  return toCorrelation(correlation.correlationId);
}

function parseResponsePayload(payload: unknown): Record<string, unknown> | null {
  const value = Buffer.isBuffer(payload) ? payload.toString('utf8') : payload;
  if (typeof value !== 'string') return null;

  try {
    const parsed: unknown = JSON.parse(value);
    return parsed !== null && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function registerResponseCorrelationHook(app: FastifyInstance, state: CorrelationState): void {
  app.addHook('onSend', async (request, reply, payload) => {
    if (reply.statusCode >= 400) return payload;

    const body = parseResponsePayload(payload);
    const step = resolveStep(request);

    if (step === 'PAR') {
      const requestUri = typeof body?.['request_uri'] === 'string' ? body['request_uri'] : null;
      request.conformance.correlation = toCorrelation(requestUri ? extractIssuerSessionId(requestUri) : null);
      return payload;
    }

    if (step !== 'TOKEN' || !request.conformance.correlation) return payload;

    const accessToken = typeof body?.['access_token'] === 'string' ? body['access_token'] : null;
    if (!accessToken) return payload;

    try {
      const tokenPayload = decodeJwt(accessToken);
      const jti = typeof tokenPayload.jti === 'string' ? tokenPayload.jti : null;
      const expiresAt = typeof tokenPayload.exp === 'number' ? tokenPayload.exp * 1000 : null;
      if (!jti || !expiresAt || expiresAt <= Date.now()) return payload;

      removeExpiredCorrelations(state);
      const correlation = { ...request.conformance.correlation, expiresAt };
      state.tokenJti.set(jti, correlation);
      state.pendingNonce.push(correlation);
    } catch (error) {
      request.log.warn({ err: error }, 'Failed to register token conformance correlation');
    }

    return payload;
  });
}

export default fp(
  async function conformancePlugin(app) {
    const state: CorrelationState = {
      pendingNonce: [],
      tokenJti: new Map()
    };

    registerResponseCorrelationHook(app, state);

    await app.register(
      createConformanceInstrumentationPlugin({
        eventSink: app.conformanceEventSink,
        resolveCorrelation: (request) => resolveCorrelation(request, app, state),
        serviceName: 'credential-issuer'
      })
    );

    app.addHook('onClose', async () => {
      state.pendingNonce = [];
      state.tokenJti.clear();
    });
  },
  { dependencies: ['db'], name: 'conformance-plugin' }
);
