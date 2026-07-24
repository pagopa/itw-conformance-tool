import fp from 'fastify-plugin';

import { createObservedEvent } from '../events/event-bus.js';
import { redactHeaders, toReportablePayload } from '../events/redaction.js';

import type { ArtifactRef, ArtifactStore } from '../artifacts/artifact-store.js';
import type { ScenarioEventSink } from '../events/event-bus.js';
import type { ObservedServiceName, ScenarioCorrelation } from '../events/event-types.js';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

export interface InstrumentationOptions {
  serviceName: ObservedServiceName;
  eventSink: ScenarioEventSink;
  artifactStore?: ArtifactStore;
  resolveCorrelation(request: FastifyRequest): ScenarioCorrelation | null;
  storeHttpExchanges?: boolean;
  maxPayloadBytes?: number;
}

interface RequestConformanceContext {
  correlation: ScenarioCorrelation | null;
  startedAt: number;
}

declare module 'fastify' {
  interface FastifyInstance {
    conformanceEventSink: ScenarioEventSink;
  }
  interface FastifyRequest {
    conformance: RequestConformanceContext;
  }
}

const DEFAULT_MAX_PAYLOAD_BYTES = 16_384;

async function maybeStoreHttpExchange(
  request: FastifyRequest,
  reply: FastifyReply,
  payload: unknown,
  options: InstrumentationOptions
): Promise<ArtifactRef | undefined> {
  if (!options.artifactStore || !options.storeHttpExchanges) return undefined;

  const maxPayloadBytes = options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES;

  return options.artifactStore.storeHttpExchange({
    request: {
      method: request.method,
      url: request.url,
      headers: redactHeaders(request.headers),
      body: toReportablePayload(request.body, maxPayloadBytes)
    },
    response: {
      statusCode: reply.statusCode,
      headers: redactHeaders(reply.getHeaders()),
      body: toReportablePayload(payload, maxPayloadBytes)
    }
  });
}

export function createConformanceInstrumentationPlugin(options: InstrumentationOptions) {
  return fp(async function conformanceInstrumentation(app: FastifyInstance) {
    if (!app.hasDecorator('conformanceEventSink')) {
      app.decorate('conformanceEventSink', options.eventSink);
    }

    app.addHook('onRequest', async (request) => {
      let correlation: ScenarioCorrelation | null = null;

      try {
        correlation = options.resolveCorrelation(request);
      } catch (error) {
        request.log.warn({ err: error }, 'Failed to resolve conformance correlation');
      }

      request.conformance = {
        correlation,
        startedAt: Date.now()
      };

      try {
        await options.eventSink.emit(
          createObservedEvent({
            name: 'http.request.received',
            correlationId: correlation?.correlationId ?? null,
            service: options.serviceName,
            requestId: request.id,
            http: {
              method: request.method,
              url: request.url,
              path: request.routeOptions.url ?? null,
              headers: redactHeaders(request.headers)
            }
          })
        );
      } catch (error) {
        request.log.warn({ err: error }, 'Failed to emit conformance request event');
      }
    });

    app.addHook('onSend', async (request, reply, payload) => {
      const ctx = request.conformance;
      let artifactRef: ArtifactRef | undefined;

      try {
        artifactRef = await maybeStoreHttpExchange(request, reply, payload, options);
      } catch (error) {
        request.log.warn({ err: error }, 'Failed to store conformance HTTP artifact');
      }

      try {
        await options.eventSink.emit(
          createObservedEvent({
            name: 'http.response.sent',
            correlationId: ctx?.correlation?.correlationId ?? null,
            service: options.serviceName,
            requestId: request.id,
            artifactRefs: artifactRef ? [artifactRef] : undefined,
            http: {
              statusCode: reply.statusCode,
              contentType: String(reply.getHeader('content-type') ?? ''),
              durationMs: ctx ? Date.now() - ctx.startedAt : undefined
            }
          })
        );
      } catch (error) {
        request.log.warn({ err: error }, 'Failed to emit conformance response event');
      }

      return payload;
    });

    app.addHook('onError', async (request, _reply, error) => {
      try {
        await options.eventSink.emit(
          createObservedEvent({
            name: 'http.request.failed',
            correlationId: request.conformance?.correlation?.correlationId ?? null,
            service: options.serviceName,
            requestId: request.id,
            error: {
              message: error.message,
              name: error.name
            }
          })
        );
      } catch (emitError) {
        request.log.warn({ err: emitError }, 'Failed to emit conformance error event');
      }
    });
  });
}
