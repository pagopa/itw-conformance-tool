import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

export type WalletInstanceStatus = 'ACTIVE' | 'REVOKED';

/**
 * Mirrors the `RevocationReason` enum of the Wallet Provider API consumed by
 * `io-react-native-wallet` (`WalletInstanceStatus.revocation_reason`).
 */
export type WalletInstanceRevocationReason =
  'CERTIFICATE_REVOKED_BY_ISSUER' | 'NEW_WALLET_INSTANCE_CREATED' | 'REVOKED_BY_USER' | 'WALLET_INSTANCE_RENEWAL';

export type RegisteredWalletInstance = {
  isRenewal: boolean;
  keyAttestation: string;
  nonce: string;
  registeredAt: string;
  revocationReason?: WalletInstanceRevocationReason;
  status: WalletInstanceStatus;
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
