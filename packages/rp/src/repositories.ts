import type { INonceRepository, ISessionRepository } from '@itw-conformance-tool/database';

export type SessionRepository = ISessionRepository;
export type NonceRepository = INonceRepository;

export interface RequestObjectServiceConfig {
  clientId: string;
  issuer: string;
  audience: string;
}
