import { resolve } from 'node:path';

import { DEFAULT_DATA_DIR, DEFAULT_PORT, loadRpConfig, type RpConfig } from '@itw-conformance-tool/rp';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: RpConfig;
  }
}

const envPlugin = fp(async (app) => {
  const configFilePath = resolve(process.cwd(), process.env.ITW_CT_CONFIG_FILE ?? 'config.ini');
  const { config, configFileFound } = loadRpConfig({ configFilePath });

  if (!configFileFound) {
    app.log.warn(
      { configFile: configFilePath, defaultsApplied: { port: DEFAULT_PORT, dataDir: DEFAULT_DATA_DIR } },
      'config.ini not found, using defaults'
    );
  }

  app.decorate('config', config);
});

export default envPlugin;
