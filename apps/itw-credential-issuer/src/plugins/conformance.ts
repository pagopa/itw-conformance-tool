import { createConformanceInstrumentationPlugin, type ScenarioCorrelation } from '@itw-conformance-tool/conformance';
import fp from 'fastify-plugin';

type ExpiringCorrelation = ScenarioCorrelation & {
  expiresAt: number;
};

type CorrelationState = {
  pendingNonce: ExpiringCorrelation[];
  tokenJti: Map<string, ExpiringCorrelation>;
};

export default fp(
  async function conformancePlugin(app) {
    const state: CorrelationState = {
      pendingNonce: [],
      tokenJti: new Map()
    };

    await app.register(
      createConformanceInstrumentationPlugin({
        eventSink: app.conformanceEventSink,
        resolveCorrelation: () => null,
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
