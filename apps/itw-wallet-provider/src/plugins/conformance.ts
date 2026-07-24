import {
  createConformanceInstrumentationPlugin,
  SqliteScenarioEventRepository
} from '@itw-conformance-tool/conformance';
import { DatabaseClient } from '@itw-conformance-tool/database';
import fp from 'fastify-plugin';

export default fp(
  async function conformancePlugin(app) {
    const dbClient = new DatabaseClient(app.config.dataDir);
    const eventSink = new SqliteScenarioEventRepository(dbClient);

    await app.register(
      createConformanceInstrumentationPlugin({
        eventSink,
        resolveCorrelation: () => null,
        serviceName: 'wallet-provider'
      })
    );

    app.addHook('onClose', async () => {
      dbClient.close();
    });
  },
  { dependencies: ['config'], name: 'conformance-plugin' }
);
