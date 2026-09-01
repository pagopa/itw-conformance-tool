import { createHash, randomBytes } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

const sha256Base64Url = (value: string): string => createHash('sha256').update(value, 'utf8').digest('base64url');

const NONCE_TTL_MS = 300_000;

type WalletNonce = {
  expiresAt: number;
};

type IssueNonceContext = {
  correlationId: string | null;
  requestId: string;
};

export type WalletNonceRegistry = {
  consume(nonce: string): boolean;
  issue(context: IssueNonceContext): Promise<string>;
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
    async issue({ correlationId, requestId }) {
      const nonce = randomBytes(32).toString('base64url');
      nonces.set(nonce, { expiresAt: Date.now() + NONCE_TTL_MS });

      await app.conformanceEventSink?.emit(
        createObservedEvent({
          name: 'wallet_provider.nonce.requested',
          correlationId,
          service: 'wallet-provider',
          requestId,
          diagnostic: {
            endpoint: '/nonce',
            method: 'GET',
            outcome: 'success',
            statusCode: 200,
            nonceSha256: sha256Base64Url(nonce)
          }
        })
      );

      return nonce;
    }
  });

  app.addHook('onClose', async () => {
    nonces.clear();
  });
};

export default fp(walletNoncePlugin, { name: 'wallet-nonce' });
