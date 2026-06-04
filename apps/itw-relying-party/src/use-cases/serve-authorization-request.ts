import { isTerminalState } from '@itw-conformance-tool/rp';

import type { SessionService } from '@itw-conformance-tool/rp';

export class SessionNotFoundError extends Error {
  readonly statusCode = 404;

  constructor(state: string) {
    super(`Session not found: ${state}`);
    this.name = 'SessionNotFoundError';
  }
}

export class SessionExpiredError extends Error {
  readonly statusCode = 410;

  constructor(state: string) {
    super(`Session has expired: ${state}`);
    this.name = 'SessionExpiredError';
  }
}

export class SessionNotServableError extends Error {
  readonly statusCode = 404;

  constructor(state: string, currentState: string) {
    super(`Session ${state} is in terminal state: ${currentState}`);
    this.name = 'SessionNotServableError';
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
