import type { PresentationSession, PresentationSessionDetails, PresentationSessionState } from './models/index.js';

export interface SessionRepository {
  create(session: PresentationSession): Promise<void>;
  findById(sessionId: string): Promise<PresentationSession | null>;
  update(sessionId: string, state: PresentationSessionState, details?: PresentationSessionDetails): Promise<void>;
  delete(sessionId: string): Promise<void>;
}

export interface NonceRepository {
  store(nonce: string, ttlSeconds: number): Promise<void>;
  consume(nonce: string): Promise<boolean>;
}

export interface RequestObjectServiceConfig {
  clientId: string;
  issuer: string;
  audience: string;
}
