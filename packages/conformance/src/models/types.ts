export type ConformancePhase = 'ISSUANCE' | 'PRESENTATION';

export type ConformanceSessionStatus = 'OPEN' | 'PASSED' | 'FAILED' | 'INCOMPLETE';

export type ConformanceCheckResult = 'PASS' | 'FAIL' | 'NOT_REACHED';

export type ConformanceStep =
  | 'PAR'
  | 'AUTHORIZE'
  | 'PRESENTATION_RESPONSE'
  | 'AUTHORIZATION_CODE'
  | 'TOKEN'
  | 'NONCE'
  | 'CREDENTIAL';

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
  id: string;
  sessionId: string;
  startedAt: string;
  closedAt?: string;
  status: ConformanceSessionStatus;
  checks: ConformanceCheck[];
}
