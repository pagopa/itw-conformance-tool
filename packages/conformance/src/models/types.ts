export type ConformancePhase = 'ISSUANCE' | 'PRESENTATION' | 'WALLET_PROVIDER_BACKEND';

export type ConformanceSessionStatus = 'OPEN' | 'PASSED' | 'FAILED' | 'INCOMPLETE';

export type ClosedConformanceSessionStatus = Exclude<ConformanceSessionStatus, 'OPEN'>;

export type ConformanceCheckResult = 'PASS' | 'FAIL' | 'NOT_REACHED';

export type ConformanceStep =
  | 'PAR'
  | 'AUTHORIZE'
  | 'PRESENTATION_RESPONSE'
  | 'AUTHORIZATION_CODE'
  | 'TOKEN'
  | 'NONCE'
  | 'CREDENTIAL'
  | 'WALLET_PROVIDER_BACKEND'
  | 'ISSUANCE';

export interface ConformanceCheck {
  requirementId: string;
  description: string;
  step: ConformanceStep;
  phase: ConformancePhase;
  result: ConformanceCheckResult;
  timestamp: string;
  httpStatus?: number;
  errorMessage?: string;
}

export interface ConformanceSession {
  sessionId: string;
  startedAt: string;
  closedAt?: string;
  status: ConformanceSessionStatus;
  checks: ConformanceCheck[];
}

export interface IConformanceSessionRepository {
  create(session: ConformanceSession): Promise<void>;
  get(sessionId: string): Promise<ConformanceSession | null>;
  appendCheck(sessionId: string, check: ConformanceCheck): Promise<void>;
  close(sessionId: string, status: ClosedConformanceSessionStatus): Promise<void>;
  markOpenSessionsIncompleteOlderThan(cutoffIso: string): Promise<number>;
}
