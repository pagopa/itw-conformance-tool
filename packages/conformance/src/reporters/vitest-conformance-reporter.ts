import { randomUUID } from 'node:crypto';

import { DatabaseClient } from '@itw-conformance-tool/database';
import { type TestResult } from 'vitest/node';

import { SqliteConformanceSessionRepository } from '../repository.js';

import type { ConformanceCheckResult, ConformancePhase, ConformanceStep } from '../models/types.js';
import type { Reporter } from 'vitest/reporters';

type ReporterTestCase = Parameters<NonNullable<Reporter['onTestCaseResult']>>[0];

type SessionStatus = 'FAILED' | 'INCOMPLETE' | 'PASSED';
type ReporterType = 'conformance-test';

type CheckContext = {
  cleanTitle: string;
  phase?: ConformancePhase;
  step?: ConformanceStep;
};

const REPORTER_CONFIG: Record<ReporterType, { phase: ConformancePhase; step: ConformanceStep }> = {
  'conformance-test': { phase: 'WALLET_PROVIDER_BACKEND', step: 'WALLET_PROVIDER_BACKEND' }
};

const PHASE_VALUES = new Set<ConformancePhase>(['ISSUANCE', 'PRESENTATION', 'WALLET_PROVIDER_BACKEND']);

const STEP_VALUES = new Set<ConformanceStep>([
  'FEDERATION',
  'PAR',
  'AUTHORIZE',
  'PRESENTATION_RESPONSE',
  'AUTHORIZATION_CODE',
  'TOKEN',
  'NONCE',
  'CREDENTIAL',
  'WALLET_PROVIDER_BACKEND'
]);

// Supports wallet-style IDs like CI_002 or RPR-001, followed by ':' or '-'.
const REQUIREMENT_ID_PATTERN = /^([A-Z]+[-_]\d+\w*)\s*[:-]/;
const CONTEXT_PREFIX_PATTERN = /^\[([A-Z_]+):([A-Z_]+)]\s*/;

function parseCheckContext(title: string): CheckContext {
  const match = CONTEXT_PREFIX_PATTERN.exec(title);
  if (!match) {
    return { cleanTitle: title };
  }

  const [, phaseCandidate, stepCandidate] = match;
  const cleanTitle = title.replace(CONTEXT_PREFIX_PATTERN, '');
  const phase = PHASE_VALUES.has(phaseCandidate as ConformancePhase) ? (phaseCandidate as ConformancePhase) : undefined;
  const step = STEP_VALUES.has(stepCandidate as ConformanceStep) ? (stepCandidate as ConformanceStep) : undefined;

  return {
    cleanTitle,
    phase,
    step
  };
}

function parseRequirementId(title: string): string {
  return REQUIREMENT_ID_PATTERN.exec(title)?.[1] ?? title;
}

function parseDescription(title: string): string {
  return title.replace(REQUIREMENT_ID_PATTERN, '').trim();
}

function mapResult(state: TestResult['state']): ConformanceCheckResult {
  if (state === 'passed') {
    return 'PASS';
  }

  if (state === 'failed') {
    return 'FAIL';
  }

  return 'NOT_REACHED';
}

function extractFailureMessage(testCase: ReporterTestCase): string {
  const firstError = testCase.result().errors?.[0];

  if (!firstError) {
    return 'Test failed without error details';
  }

  if (typeof firstError === 'string') {
    return firstError;
  }

  if (typeof firstError === 'object' && 'message' in firstError) {
    const message = (firstError as { message?: unknown }).message;
    if (typeof message === 'string' && message.length > 0) {
      return message;
    }
  }

  return String(firstError);
}

function resolveFinalStatus(results: readonly ConformanceCheckResult[]): SessionStatus {
  if (results.includes('FAIL')) {
    return 'FAILED';
  }

  if (results.includes('NOT_REACHED')) {
    return 'INCOMPLETE';
  }

  return 'PASSED';
}

export class VitestConformanceReporter implements Reporter {
  private readonly reporterType: ReporterType;
  private readonly phase: ConformancePhase;
  private readonly step: ConformanceStep;
  private readonly results: ConformanceCheckResult[] = [];
  private readonly failedPhases = new Set<ConformancePhase>();

  private client: DatabaseClient | undefined;
  private repository: SqliteConformanceSessionRepository | undefined;
  private sessionId: string | undefined;

  constructor(type: ReporterType) {
    this.reporterType = type;
    const config = REPORTER_CONFIG[type];
    this.phase = config.phase;
    this.step = config.step;
  }

  async onTestRunStart(): Promise<void> {
    const dataDir = process.env.ITW_CT_DATA_DIR;
    if (!dataDir) {
      throw new Error('Missing required env: ITW_CT_DATA_DIR');
    }
    this.client = new DatabaseClient({ dataDir });
    this.repository = new SqliteConformanceSessionRepository(this.client.db);
    this.sessionId = randomUUID();
    this.results.length = 0;
    this.failedPhases.clear();

    await this.repository.create({
      sessionId: this.sessionId,
      startedAt: new Date().toISOString(),
      status: 'OPEN',
      checks: []
    });
  }

  async onTestCaseResult(testCase: ReporterTestCase): Promise<void> {
    if (!this.repository || !this.sessionId) {
      return;
    }

    const context = parseCheckContext(testCase.name);
    const phase = context.phase ?? this.phase;
    const step = context.step ?? this.step;
    const state = testCase.result().state;
    let result = mapResult(state);

    // Conformance matrix tests may short-circuit after the first failure.
    // In that case Vitest marks later tests as passed due early returns, but
    // they are semantically NOT_REACHED for conformance reporting.
    if (this.reporterType === 'conformance-test' && this.failedPhases.has(phase) && state === 'passed') {
      result = 'NOT_REACHED';
    }

    if (result === 'FAIL') {
      this.failedPhases.add(phase);
    }

    const errorMessage = result === 'FAIL' ? extractFailureMessage(testCase) : undefined;

    await this.repository.appendCheck(this.sessionId, {
      requirementId: parseRequirementId(context.cleanTitle),
      description: parseDescription(context.cleanTitle),
      step,
      phase,
      result,
      timestamp: new Date().toISOString(),
      errorMessage
    });

    this.results.push(result);
  }

  async onTestRunEnd(): Promise<void> {
    if (!this.repository || !this.sessionId || !this.client) {
      return;
    }

    const status = resolveFinalStatus(this.results);
    await this.repository.close(this.sessionId, status);

    await this.client.close();
    this.repository = undefined;
    this.client = undefined;
    this.sessionId = undefined;
  }
}
