export type PresentationSessionState = 'pending' | 'verified' | 'rejected' | 'expired' | 'denied';

export type PresentationFlowType = 'presentation';

export type PresentationValues = Array<Record<string, string | null>>;

export interface PresentationSession {
  sessionId: string;
  state: PresentationSessionState;
  flowType: PresentationFlowType;
  requestUri?: string;
  redirectUri?: string;
  values: PresentationValues;
  createdAt: Date;
  expiresAt: Date;
  verifiedAt?: Date;
}

export interface PresentationSessionDetails {
  redirectUri?: string;
  values: PresentationValues;
}

export function isTerminalState(state: PresentationSessionState): boolean {
  return ['verified', 'rejected', 'expired', 'denied'].includes(state);
}

export function isExpiredNow(expiresAt: Date): boolean {
  return new Date() > expiresAt;
}

export function mapToDbState(state: PresentationSessionState): string {
  const stateMap: Record<PresentationSessionState, string> = {
    pending: 'pending',
    verified: 'verified',
    rejected: 'rejected',
    expired: 'expired',
    denied: 'denied'
  };
  return stateMap[state];
}

export function createPresentationSession(sessionId: string, ttlSeconds = 300): PresentationSession {
  const now = new Date();
  return {
    sessionId,
    state: 'pending',
    flowType: 'presentation',
    values: [],
    createdAt: now,
    expiresAt: new Date(now.getTime() + ttlSeconds * 1000)
  };
}

export function recordToPresentationSession(record: Record<string, unknown>): PresentationSession {
  const detailsStr = record.details ? String(record.details) : '{"redirectUri":"","values":[]}';
  let details: PresentationSessionDetails;

  try {
    details = JSON.parse(detailsStr) as PresentationSessionDetails;
  } catch {
    details = { redirectUri: '', values: [] };
  }

  return {
    sessionId: String(record.id),
    state: String(record.state) as PresentationSessionState,
    flowType: 'presentation',
    redirectUri: details.redirectUri,
    values: details.values,
    createdAt: new Date(String(record.created_at)),
    expiresAt: new Date(String(record.expires_at)),
    verifiedAt: record.verified_at ? new Date(String(record.verified_at)) : undefined
  };
}

export function serializeDetails(details: PresentationSessionDetails): string {
  return JSON.stringify(details);
}

export function parseDetails(detailsStr: string): PresentationSessionDetails {
  try {
    return JSON.parse(detailsStr) as PresentationSessionDetails;
  } catch {
    return { redirectUri: '', values: [] };
  }
}
