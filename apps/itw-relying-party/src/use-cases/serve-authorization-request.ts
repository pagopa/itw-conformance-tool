import { isTerminalState } from '@itw-conformance-tool/rp';

import type { SessionService } from '@itw-conformance-tool/rp';

export class SessionNotFoundError extends Error {
  readonly state: string;
  readonly statusCode = 404;

  constructor(state: string) {
    super('Session not found');
    this.name = 'SessionNotFoundError';
    this.state = state;
  }
}

export class SessionExpiredError extends Error {
  readonly state: string;
  readonly statusCode = 410;

  constructor(state: string) {
    super('Session has expired');
    this.name = 'SessionExpiredError';
    this.state = state;
  }
}

export class SessionNotServableError extends Error {
  readonly state: string;
  readonly currentState: Parameters<typeof isTerminalState>[0];
  readonly statusCode = 404;

  constructor(state: string, currentState: Parameters<typeof isTerminalState>[0]) {
    super('Session not found');
    this.name = 'SessionNotServableError';
    this.state = state;
    this.currentState = currentState;
  }
}

export interface ServeAuthorizationRequestInput {
  sessionService: SessionService;
  state: string;
}

/** Retrieves the signed Request Object JWT for a given OAuth2 state.
 *
 * @returns the signed Request Object JWT string.
 */
export async function serveAuthorizationRequestUseCase(input: ServeAuthorizationRequestInput): Promise<string> {
  const { state, sessionService } = input;
  const session = await sessionService.get(state);

  if (!session) {
    throw new SessionNotFoundError(state);
  }

  if (session.state === 'expired') {
    throw new SessionExpiredError(state);
  }

  if (isTerminalState(session.state)) {
    throw new SessionNotServableError(state, session.state);
  }

  if (session.state === 'pending') {
    await sessionService.update(state, 'checking');
  }

  return session.jwt;
}
