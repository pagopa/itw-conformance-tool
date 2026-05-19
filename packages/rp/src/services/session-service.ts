import {
  createPresentationSession,
  isExpiredNow,
  isTerminalState,
  mapToDbState,
  recordToPresentationSession,
  serializeDetails,
  type PresentationFlowType,
  type PresentationSession,
  type PresentationSessionState,
  type PresentationValues
} from '../models/presentation-session.js';

import type { ISessionRepository } from '@itw-conformance-tool/database';

const DEFAULT_TTL_MS = 5 * 60 * 1000;

export interface CreateSessionInput {
  id: string;
  jwt: string;
  flowType: PresentationFlowType;
  ttlMs?: number;
}

export interface SessionUpdateOptions {
  redirectUri?: string | null;
  values?: PresentationValues | null;
}

export type TransitionalState = Exclude<PresentationSessionState, 'pending'>;

export class SessionService {
  readonly #repo: ISessionRepository;

  constructor(repo: ISessionRepository) {
    this.#repo = repo;
  }

  async create(input: CreateSessionInput): Promise<PresentationSession> {
    const { id, jwt, flowType, ttlMs = DEFAULT_TTL_MS } = input;
    const session = createPresentationSession({ id, jwt, flowType, ttlMs });

    await this.#repo.insert(id, jwt);
    await this.#repo.update(
      id,
      mapToDbState(session.state),
      serializeDetails({
        rpState: session.state,
        flowType: session.flowType,
        redirectUri: session.redirectUri,
        values: session.values,
        expiresAt: session.expiresAt
      })
    );

    return session;
  }

  async get(id: string): Promise<PresentationSession | undefined> {
    const record = await this.#repo.get(id);
    if (record === undefined) {
      return undefined;
    }

    const session = recordToPresentationSession(record);

    if (isExpiredNow(session)) {
      await this.#persist(id, 'expired', {
        flowType: session.flowType,
        redirectUri: session.redirectUri,
        values: session.values,
        expiresAt: session.expiresAt
      });
      return { ...session, state: 'expired' };
    }

    return session;
  }

  async update(id: string, newState: TransitionalState, options: SessionUpdateOptions = {}): Promise<void> {
    const record = await this.#repo.get(id);
    if (record === undefined) {
      throw new Error(`Session not found: ${id}`);
    }

    const current = recordToPresentationSession(record);
    if (isTerminalState(current.state)) {
      return;
    }

    const nextRedirectUri = options.redirectUri !== undefined ? options.redirectUri : current.redirectUri;
    const nextValues = options.values !== undefined ? options.values : current.values;

    await this.#persist(id, newState, {
      flowType: current.flowType,
      redirectUri: nextRedirectUri,
      values: nextValues,
      expiresAt: current.expiresAt
    });
  }

  async delete(id: string): Promise<void> {
    await this.#repo.delete(id);
  }

  async #persist(
    id: string,
    rpState: PresentationSessionState,
    detail: {
      flowType: PresentationFlowType;
      redirectUri: string | null;
      values: PresentationValues | null;
      expiresAt: number;
    }
  ): Promise<void> {
    await this.#repo.update(
      id,
      mapToDbState(rpState),
      serializeDetails({
        rpState,
        flowType: detail.flowType,
        redirectUri: detail.redirectUri,
        values: detail.values,
        expiresAt: detail.expiresAt
      })
    );
  }
}
