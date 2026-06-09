import type { SessionService } from '@itw-conformance-tool/rp';
import type { PresentationValues } from '@itw-conformance-tool/rp';

export interface GetPresentationStatusInput {
  state: string;
  sessionService: SessionService;
}

export interface PresentationStatusResult {
  redirect_uri: string;
  values?: PresentationValues;
}

export class SessionNotFoundError extends Error {
  constructor(state: string) {
    super(`Session not found: ${state}`);
    this.name = 'SessionNotFoundError';
  }
}

function appendResponseCodeSuccess(redirectUri: string): string {
  if (redirectUri.includes('response_code=')) {
    return redirectUri;
  }

  const separator = redirectUri.includes('?') ? '&' : '?';
  return `${redirectUri}${separator}response_code=success`;
}

export async function getPresentationStatusUseCase(
  input: GetPresentationStatusInput
): Promise<PresentationStatusResult> {
  const session = await input.sessionService.get(input.state);
  if (session === undefined) {
    throw new SessionNotFoundError(input.state);
  }

  const { redirectUri, state, values } = session;

  if (state === 'verified') {
    if (redirectUri === null) {
      await input.sessionService.delete(input.state);
      return { redirect_uri: 'error.html?response_code=unexpected' };
    }

    return {
      redirect_uri: appendResponseCodeSuccess(redirectUri),
      values: values ?? undefined
    };
  }

  if (state === 'rejected') {
    await input.sessionService.delete(input.state);
    return { redirect_uri: 'rejected-error.html?response_code=rejected' };
  }

  if (state === 'denied') {
    await input.sessionService.delete(input.state);
    return { redirect_uri: 'error.html?response_code=denied' };
  }

  if (state === 'expired') {
    await input.sessionService.delete(input.state);
    return { redirect_uri: 'timeout.html?response_code=expired' };
  }

  if (state === 'checking') {
    return { redirect_uri: '?response_code=checking' };
  }

  return { redirect_uri: '?response_code=pending' };
}
