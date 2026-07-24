import {
  createConformanceInstrumentationPlugin,
  SqliteScenarioEventRepository,
  type ScenarioCorrelation
} from '@itw-conformance-tool/conformance';
import { DatabaseClient } from '@itw-conformance-tool/database';
import fp from 'fastify-plugin';

import type { FastifyRequest } from 'fastify';

function getStringParam(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function toCorrelation(correlationId: string | null): ScenarioCorrelation | null {
  return correlationId ? { correlationId, scenarioId: correlationId } : null;
}

function resolveCorrelation(request: FastifyRequest): ScenarioCorrelation | null {
  const route = request.routeOptions.url;

  if (route === '/auth/request/:state' || route === '/callback/:state') {
    const correlationId = getStringParam((request.params as Record<string, unknown>).state);
    return toCorrelation(correlationId);
  }

  if (route === '/auth/response') {
    const sessionId = getStringParam((request.query as Record<string, unknown>).session_id);
    if (!sessionId) return null;

    try {
      const requestObject = request.server.repository.requestObject.getBySessionId(sessionId);
      return toCorrelation(requestObject.id);
    } catch {
      return null;
    }
  }

  return null;
}

export default fp(
  async function conformancePlugin(app) {
    const dbClient = new DatabaseClient(app.config.DATA_DIR);
    const eventSink = new SqliteScenarioEventRepository(dbClient);

    await app.register(
      createConformanceInstrumentationPlugin({
        eventSink,
        resolveCorrelation,
        serviceName: 'relying-party',
        storeHttpExchanges: true
      })
    );

    app.addHook('onClose', async () => {
      dbClient.close();
    });
  },
  { dependencies: ['repository-plugin'], name: 'conformance-plugin' }
);
