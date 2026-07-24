import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

export type RegisteredWalletInstance = {
  keyAttestation: string;
  nonce: string;
  registeredAt: string;
};

export type RegisteredWalletInstances = Map<string, RegisteredWalletInstance>;

declare module 'fastify' {
  interface FastifyInstance {
    registeredWalletInstances: RegisteredWalletInstances;
  }
}

const walletInstanceRegistryPlugin: FastifyPluginAsync = async (app) => {
  app.decorate('registeredWalletInstances', new Map<string, RegisteredWalletInstance>());
};

export default fp(walletInstanceRegistryPlugin, {
  name: 'wallet-instance-registry'
});
