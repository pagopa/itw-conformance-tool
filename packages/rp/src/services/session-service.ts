import { createPresentationSession, type PresentationSessionDetails } from '../models/index.js';

import type { SessionRepository } from '../repositories.js';

export type TransitionalState = 'pending' | 'verified' | 'rejected';

export interface CreateSessionInput {
  sessionId: string;
  ttlSeconds?: number;
}

export interface SessionUpdateOptions {
  redirectUri?: string;
  values?: Array<Record<string, string | null>>;
}

export class SessionService {
  readonly #sessionRepository: SessionRepository;

  constructor(sessionRepository: SessionRepository) {
    this.#sessionRepository = sessionRepository;
  }

  async create(input: CreateSessionInput): Promise<string> {
    const session = createPresentationSession(input.sessionId, input.ttlSeconds);
    await this.#sessionRepository.create(session);
    return session.sessionId;
  }

  async get(sessionId: string) {
    return this.#sessionRepository.findById(sessionId);
  }

  async update(sessionId: string, state: TransitionalState, options?: SessionUpdateOptions) {
    const details: PresentationSessionDetails = {
      redirectUri: options?.redirectUri,
      values: options?.values || []
    };
    await this.#sessionRepository.update(sessionId, state, details);
  }

  async delete(sessionId: string) {
    await this.#sessionRepository.delete(sessionId);
  }
}

export { type SessionRepository } from '../repositories.js';
