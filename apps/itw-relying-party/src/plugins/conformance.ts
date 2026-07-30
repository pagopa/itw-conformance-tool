import {
  createConformanceInstrumentationPlugin,
  SqliteScenarioEventRepository
} from '@itw-conformance-tool/conformance';
import { DatabaseClient } from '@itw-conformance-tool/database';
import fp from 'fastify-plugin';

export default fp(
  async function conformancePlugin(app) {
    const dbClient = new DatabaseClient(app.config.DATA_DIR);
    const eventSink = new SqliteScenarioEventRepository(dbClient);

    await app.register(
      createConformanceInstrumentationPlugin({
        eventSink,
        // The protocol correlationId mechanism is temporarily disabled: every RP
        // event is emitted uncorrelated (correlationId: null) and scenarios adopt
        // it as post-start evidence narrowed by diagnostics (see the presentation
        // scenario factories' `allow-uncorrelated-post-start` + `match`). Mirrors
        // the credential-issuer plugin.
        resolveCorrelation: () => null,
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
