import type { SessionRecord, SessionState } from '@itw-conformance-tool/database';

export type PresentationSessionState = 'checking' | 'denied' | 'expired' | 'pending' | 'rejected' | 'verified';

export type PresentationFlowType = 'cross-device' | 'same-device';

export type PresentationValues = Record<string, null | string>[];

export interface PresentationSession {
  id: string;
  state: PresentationSessionState;
  flowType: PresentationFlowType;
  jwt: string;
  redirectUri: string | null;
  values: PresentationValues | null;
  expiresAt: number;
  createdAt: number;
}

interface PersistedDetails {
  rpState: PresentationSessionState;
  flowType: PresentationFlowType;
  redirectUri: string | null;
  values: PresentationValues | null;
  expiresAt: number;
}

const TERMINAL_STATES: ReadonlySet<PresentationSessionState> = new Set(['verified', 'rejected', 'denied', 'expired']);

export function isTerminalState(state: PresentationSessionState): boolean {
  return TERMINAL_STATES.has(state);
}

// Maps the rich RP state machine (6 values) onto the database's reduced one (3 values),
// because @itw-conformance-tool/database persists only 'pending' | 'completed' | 'failed'.
export function mapToDbState(state: PresentationSessionState): SessionState {
  if (state === 'verified') {
    return 'completed';
  }
  if (state === 'rejected' || state === 'denied' || state === 'expired') {
    return 'failed';
  }
  return 'pending';
}

export function serializeDetails(details: PersistedDetails): string {
  return JSON.stringify(details);
}

export function parseDetails(response: string | null): PersistedDetails | undefined {
  if (response === null) {
    return undefined;
  }
  return JSON.parse(response) as PersistedDetails;
}

export function recordToPresentationSession(record: SessionRecord): PresentationSession {
  const details = parseDetails(record.response);
  if (details === undefined) {
    throw new Error(`Session ${record.id} has no persisted details`);
  }
  if (record.requestObject === null) {
    throw new Error(`Session ${record.id} has no JWT`);
  }
  return {
    id: record.id,
    state: details.rpState,
    flowType: details.flowType,
    jwt: record.requestObject,
    redirectUri: details.redirectUri,
    values: details.values,
    expiresAt: details.expiresAt,
    createdAt: record.createdAt
  };
}

export function isExpiredNow(
  session: Pick<PresentationSession, 'expiresAt' | 'state'>,
  nowMs: number = Date.now()
): boolean {
  if (isTerminalState(session.state)) {
    return false;
  }
  return session.expiresAt < nowMs;
}

export function createPresentationSession(input: {
  id: string;
  jwt: string;
  flowType: PresentationFlowType;
  ttlMs: number;
  createdAtMs?: number;
}): PresentationSession {
  const createdAt = input.createdAtMs ?? Date.now();
  return {
    id: input.id,
    state: 'pending',
    flowType: input.flowType,
    jwt: input.jwt,
    redirectUri: null,
    values: null,
    expiresAt: createdAt + input.ttlMs,
    createdAt
  };
}
