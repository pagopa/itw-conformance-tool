import { randomBytes } from 'node:crypto';

import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

const NONCE_TTL_MS = 300_000;

type WalletNonce = {
  expiresAt: number;
};

export type WalletNonceRegistry = {
  consume(nonce: string): boolean;
  issue(): string;
};

declare module 'fastify' {
  interface FastifyInstance {
    walletNonces: WalletNonceRegistry;
  }
}

const walletNoncePlugin: FastifyPluginAsync = async (app) => {
  const nonces = new Map<string, WalletNonce>();

  app.decorate('walletNonces', {
    consume(nonce) {
      const storedNonce = nonces.get(nonce);
      nonces.delete(nonce);
      return storedNonce !== undefined && storedNonce.expiresAt > Date.now();
    },
    issue() {
      const nonce = randomBytes(32).toString('base64url');
      nonces.set(nonce, { expiresAt: Date.now() + NONCE_TTL_MS });
      return nonce;
    }
  });

  app.addHook('onClose', async () => {
    nonces.clear();
  });
};

export default fp(walletNoncePlugin, { name: 'wallet-nonce' });
