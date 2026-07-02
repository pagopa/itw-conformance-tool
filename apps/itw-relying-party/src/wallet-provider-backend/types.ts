import type { JWK } from 'jose';

export type FederationAccessLogEntry = {
  method: string;
  path: string;
  timestamp: string;
};

export type AttestationIssuanceLogEntry = {
  ephemeralKeyThumbprint: string;
  timestamp: string;
};

export type RevocationNotificationEvent = {
  instanceId: string;
  revokedAt: string;
  notifiedAt: string;
};

export type WalletInstanceRecord = {
  ownerToken: string;
  status: 'ACTIVE' | 'REVOKED';
  issuedAt: string;
  revokedAt?: string;
  notifiedAt?: string;
};

export type WalletProviderBackendState = {
  baseUrl: string;
  federationPrivateKeyPem: string;
  x5cCertPem: string;
  seenEphemeralKeyThumbprints: Set<string>;
  nonces: Map<string, number>;
  instances: Map<string, WalletInstanceRecord>;
  federationAccessLog: FederationAccessLogEntry[];
  attestationIssuanceLog: AttestationIssuanceLogEntry[];
  revocationNotifications: RevocationNotificationEvent[];
};

export type WalletProviderBackendKeys = {
  federationPrivateKeyPem: string;
  x5cCertPem: string;
};

export type WalletProviderBackendDeps = {
  baseUrl: string;
  keys: WalletProviderBackendKeys;
};

export type JsonErrorBody = {
  error: string;
  error_description: string;
};

export type { JWK };
