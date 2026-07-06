import type {
  ConformanceCheck,
  ConformanceCheckResult,
  ConformancePhase,
  ConformanceSession,
  ConformanceStep,
  IConformanceSessionRepository
} from '../models/types.js';

const DEFAULT_TTL_SECONDS = 3600;

const ISSUANCE_FLOW_STEPS: ConformanceStep[] = [
  'PAR',
  'AUTHORIZE',
  'PRESENTATION_RESPONSE',
  'AUTHORIZATION_CODE',
  'TOKEN',
  'NONCE',
  'CREDENTIAL'
];

const PRESENTATION_FLOW_STEPS: ConformanceStep[] = ['AUTHORIZE', 'PRESENTATION_RESPONSE'];
const WALLET_PROVIDER_BACKEND_FLOW_STEPS: ConformanceStep[] = ['WALLET_PROVIDER_BACKEND'];

type VitestAssertionStatus = 'passed' | 'failed' | 'pending';

export interface JsonReporterAssertionResult {
  ancestorTitles: string[];
  duration: number;
  failureMessages: string[];
  fullName: string;
  location: {
    column: number;
    line: number;
  };
  meta: {
    httpStatus?: number;
    phase: ConformancePhase;
    requirementId: string;
    result: ConformanceCheckResult;
    step: ConformanceStep;
    timestamp: string;
  };
  status: VitestAssertionStatus;
  title: string;
}

export interface JsonReporterTestResult {
  assertionResults: JsonReporterAssertionResult[];
  endTime: number;
  message: string;
  name: string;
  startTime: number;
  status: VitestAssertionStatus;
}

export interface JsonReporterResult {
  coverageMap: Record<string, never>;
  numFailedTestSuites: number;
  numFailedTests: number;
  numPassedTestSuites: number;
  numPassedTests: number;
  numPendingTestSuites: number;
  numPendingTests: number;
  numTodoTests: number;
  numTotalTestSuites: number;
  numTotalTests: number;
  startTime: number;
  success: boolean;
  testResults: JsonReporterTestResult[];
  meta: {
    closedAt?: string;
    runId: string;
    startedAt: string;
    status: ConformanceSession['status'];
  };
}

export interface JsonReporterBuildOptions {
  now?: Date;
  ttlSeconds?: number;
}

export interface JsonReporterBuildResult {
  jsonReporter: JsonReporterResult;
  lazilyClosed: boolean;
  session: ConformanceSession;
}

function parseIsoTimestamp(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? fallback : parsed;
}

function getSessionPhases(session: ConformanceSession): ConformancePhase[] {
  const allPhases: ConformancePhase[] = ['ISSUANCE', 'PRESENTATION', 'WALLET_PROVIDER_BACKEND'];
  return allPhases;
}

function getExpectedSteps(phase: ConformancePhase): ConformanceStep[] {
  if (phase === 'PRESENTATION') {
    return PRESENTATION_FLOW_STEPS;
  }

  if (phase === 'WALLET_PROVIDER_BACKEND') {
    return WALLET_PROVIDER_BACKEND_FLOW_STEPS;
  }

  return ISSUANCE_FLOW_STEPS;
}

function getFlowName(phase: ConformancePhase): string {
  if (phase === 'PRESENTATION') {
    return 'Presentation Flow';
  }

  if (phase === 'WALLET_PROVIDER_BACKEND') {
    return 'Wallet Provider Backend';
  }

  return 'Issuance Flow';
}

function toAssertionStatus(result: ConformanceCheckResult): VitestAssertionStatus {
  if (result === 'PASS') {
    return 'passed';
  }
  if (result === 'FAIL') {
    return 'failed';
  }
  return 'pending';
}

function toFailureMessages(check: ConformanceCheck): string[] {
  if (check.result !== 'FAIL') {
    return [];
  }

  const messages: string[] = [];
  if (check.errorMessage) {
    messages.push(check.errorMessage);
  }
  if (check.httpStatus !== undefined) {
    messages.push(`HTTP ${check.httpStatus}`);
  }

  return messages;
}

function toSuiteStatus(assertions: JsonReporterAssertionResult[]): VitestAssertionStatus {
  if (assertions.some((assertion) => assertion.status === 'failed')) {
    return 'failed';
  }

  if (assertions.every((assertion) => assertion.status === 'pending')) {
    return 'pending';
  }

  return 'passed';
}

function toPlaceholderAssertion(phase: ConformancePhase, step: ConformanceStep): JsonReporterAssertionResult {
  const flowName = getFlowName(phase);

  return {
    ancestorTitles: [flowName, step],
    duration: 0,
    failureMessages: [],
    fullName: `${flowName} ${step} not reached`,
    location: { column: 1, line: 1 },
    meta: {
      phase,
      requirementId: `${phase}-${step}-NOT_REACHED`,
      result: 'NOT_REACHED',
      step,
      timestamp: ''
    },
    status: 'pending',
    title: 'step not reached'
  };
}

function buildSuite(
  phase: ConformancePhase,
  step: ConformanceStep,
  checks: ConformanceCheck[],
  fallbackStart: number,
  fallbackEnd: number
): JsonReporterTestResult {
  const sortedChecks = checks.slice().sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp));

  const assertions = sortedChecks.map((check, index) => {
    const flowName = getFlowName(phase);

    const assertion: JsonReporterAssertionResult & { _time: number } = {
      ancestorTitles: [flowName, step],
      duration: 0,
      failureMessages: toFailureMessages(check),
      fullName: `${flowName} ${step} ${check.description}`,
      location: { column: 1, line: index + 1 },
      meta: {
        httpStatus: check.httpStatus,
        phase: check.phase,
        requirementId: check.requirementId,
        result: check.result,
        step: check.step,
        timestamp: check.timestamp
      },
      status: toAssertionStatus(check.result),
      title: check.description,
      _time: parseIsoTimestamp(check.timestamp, fallbackStart)
    };

    return assertion;
  });

  const normalizedAssertions = assertions.length > 0 ? assertions : [toPlaceholderAssertion(phase, step)];
  const assertionTimes = assertions.map((assertion) => assertion._time);
  const startTime = assertionTimes.length > 0 ? Math.min(...assertionTimes) : fallbackStart;
  const endTime = assertionTimes.length > 0 ? Math.max(...assertionTimes) : fallbackEnd;

  return {
    assertionResults: normalizedAssertions.map((assertion) => {
      const clone = { ...assertion } as JsonReporterAssertionResult & { _time?: number };
      delete clone._time;
      return clone;
    }),
    endTime,
    message: '',
    name: step,
    startTime,
    status: toSuiteStatus(normalizedAssertions)
  };
}

function aggregateCounts(suites: JsonReporterTestResult[]) {
  let numPassedTests = 0;
  let numFailedTests = 0;
  let numPendingTests = 0;

  for (const suite of suites) {
    for (const assertion of suite.assertionResults) {
      if (assertion.status === 'passed') {
        numPassedTests += 1;
      } else if (assertion.status === 'failed') {
        numFailedTests += 1;
      } else {
        numPendingTests += 1;
      }
    }
  }

  const numPassedTestSuites = suites.filter((suite) => suite.status === 'passed').length;
  const numFailedTestSuites = suites.filter((suite) => suite.status === 'failed').length;
  const numPendingTestSuites = suites.filter((suite) => suite.status === 'pending').length;

  return {
    numFailedTestSuites,
    numFailedTests,
    numPassedTestSuites,
    numPassedTests,
    numPendingTestSuites,
    numPendingTests,
    numTotalTestSuites: suites.length,
    numTotalTests: numPassedTests + numFailedTests + numPendingTests
  };
}

function isStaleOpenSession(session: ConformanceSession, now: Date, ttlSeconds: number): boolean {
  if (session.status !== 'OPEN') {
    return false;
  }

  const startedAt = Date.parse(session.startedAt);
  if (Number.isNaN(startedAt)) {
    return false;
  }

  return startedAt + ttlSeconds * 1000 <= now.getTime();
}

export async function loadSessionForReport(
  repository: IConformanceSessionRepository,
  sessionId: string,
  options: JsonReporterBuildOptions = {}
): Promise<{ lazilyClosed: boolean; session: ConformanceSession } | null> {
  const now = options.now ?? new Date();
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;

  let session = await repository.get(sessionId);
  if (!session) {
    return null;
  }

  let lazilyClosed = false;
  if (isStaleOpenSession(session, now, ttlSeconds)) {
    await repository.close(sessionId, 'INCOMPLETE');
    lazilyClosed = true;

    const updated = await repository.get(sessionId);
    if (updated) {
      session = updated;
    } else {
      session = {
        ...session,
        closedAt: now.toISOString(),
        status: 'INCOMPLETE'
      };
    }
  }

  return { lazilyClosed, session };
}

export function buildJsonReporterFromSession(session: ConformanceSession): JsonReporterResult {
  const startTime = parseIsoTimestamp(session.startedAt, Date.now());
  const endTime = parseIsoTimestamp(session.closedAt, Date.now());
  const phases = getSessionPhases(session);
  const testResults: JsonReporterTestResult[] = [];

  for (const phase of phases) {
    const expectedSteps = getExpectedSteps(phase);
    const checksByStep = new Map<ConformanceStep, ConformanceCheck[]>();

    for (const step of expectedSteps) {
      checksByStep.set(step, []);
    }

    for (const check of session.checks) {
      if (check.phase !== phase) {
        continue;
      }

      if (!checksByStep.has(check.step)) {
        checksByStep.set(check.step, []);
      }

      checksByStep.get(check.step)?.push(check);
    }

    const orderedSteps = [
      ...expectedSteps,
      ...Array.from(checksByStep.keys()).filter((step) => !expectedSteps.includes(step))
    ];

    for (const step of orderedSteps) {
      testResults.push(buildSuite(phase, step, checksByStep.get(step) ?? [], startTime, endTime));
    }
  }

  const counts = aggregateCounts(testResults);

  return {
    ...counts,
    coverageMap: {},
    meta: {
      closedAt: session.closedAt,
      runId: session.sessionId,
      startedAt: session.startedAt,
      status: session.status
    },
    numTodoTests: 0,
    startTime,
    success: session.status === 'PASSED' && counts.numFailedTests === 0,
    testResults
  };
}

export async function buildJsonReporterFromRepository(
  repository: IConformanceSessionRepository,
  sessionId: string,
  options: JsonReporterBuildOptions = {}
): Promise<JsonReporterBuildResult | null> {
  const loaded = await loadSessionForReport(repository, sessionId, options);
  if (!loaded) {
    return null;
  }

  return {
    jsonReporter: buildJsonReporterFromSession(loaded.session),
    lazilyClosed: loaded.lazilyClosed,
    session: loaded.session
  };
}
