import { describe, expect, it } from 'vitest';

import {
  buildJsonReporterFromRepository,
  buildJsonReporterFromSession,
  type JsonReporterResult
} from '../reporters/json-reporter.js';

import type {
  ClosedConformanceSessionStatus,
  ConformanceCheck,
  ConformanceSession,
  IConformanceSessionRepository
} from '../models/types.js';

class InMemoryConformanceSessionRepository implements IConformanceSessionRepository {
  private readonly sessions = new Map<string, ConformanceSession>();

  async create(session: ConformanceSession): Promise<void> {
    this.sessions.set(session.sessionId, structuredClone(session));
  }

  async get(sessionId: string): Promise<ConformanceSession | null> {
    const found = this.sessions.get(sessionId);
    return found ? structuredClone(found) : null;
  }

  async appendCheck(sessionId: string, check: ConformanceCheck): Promise<void> {
    const current = this.sessions.get(sessionId);
    if (current?.status !== 'OPEN') {
      return;
    }

    current.checks.push(check);
  }

  async close(sessionId: string, status: ClosedConformanceSessionStatus): Promise<void> {
    const current = this.sessions.get(sessionId);
    if (current?.status !== 'OPEN') {
      return;
    }

    current.status = status;
    current.closedAt = new Date().toISOString();
  }

  async markOpenSessionsIncompleteOlderThan(): Promise<number> {
    return 0;
  }
}

function makeSession(): ConformanceSession {
  return {
    checks: [
      {
        description: 'PAR request contains a valid Wallet Attestation JWT',
        phase: 'ISSUANCE',
        requirementId: 'IT-WALLET-1.4-§4.2.1',
        result: 'PASS',
        step: 'PAR',
        timestamp: '2026-06-12T12:00:05.000Z'
      },
      {
        description: 'Token request includes a valid DPoP proof',
        errorMessage: 'invalid dpop',
        httpStatus: 400,
        phase: 'ISSUANCE',
        requirementId: 'IT-WALLET-1.4-§4.3.2',
        result: 'FAIL',
        step: 'TOKEN',
        timestamp: '2026-06-12T12:00:15.000Z'
      }
    ],
    sessionId: '550e8400-e29b-41d4-a716-446655440000',
    startedAt: '2026-06-12T12:00:00.000Z',
    status: 'FAILED'
  };
}

function expectVitestShape(jsonReporter: JsonReporterResult): void {
  expect(typeof jsonReporter.numTotalTestSuites).toBe('number');
  expect(typeof jsonReporter.numPassedTestSuites).toBe('number');
  expect(typeof jsonReporter.numFailedTestSuites).toBe('number');
  expect(typeof jsonReporter.numPendingTestSuites).toBe('number');
  expect(typeof jsonReporter.numTotalTests).toBe('number');
  expect(typeof jsonReporter.numPassedTests).toBe('number');
  expect(typeof jsonReporter.numFailedTests).toBe('number');
  expect(typeof jsonReporter.numPendingTests).toBe('number');
  expect(typeof jsonReporter.numTodoTests).toBe('number');
  expect(typeof jsonReporter.startTime).toBe('number');
  expect(typeof jsonReporter.success).toBe('boolean');
  expect(Array.isArray(jsonReporter.testResults)).toBe(true);
  expect(jsonReporter.coverageMap).toEqual({});
}

describe('json-reporter', () => {
  it('maps a conformance session to Vitest-compatible JsonReporter fields', () => {
    const jsonReporter = buildJsonReporterFromSession(makeSession());

    expectVitestShape(jsonReporter);
    expect(jsonReporter.meta.runId).toBe('550e8400-e29b-41d4-a716-446655440000');
    expect(jsonReporter.numTotalTestSuites).toBe(7);
    expect(jsonReporter.numPassedTests).toBe(1);
    expect(jsonReporter.numFailedTests).toBe(1);
    expect(jsonReporter.numPendingTests).toBe(5);
    expect(jsonReporter.success).toBe(false);

    const tokenSuite = jsonReporter.testResults.find((suite) => suite.name === 'TOKEN');
    expect(tokenSuite?.status).toBe('failed');
    expect(tokenSuite?.assertionResults[0]?.failureMessages).toContain('invalid dpop');
  });

  it('lazy-closes stale OPEN sessions as INCOMPLETE before rendering', async () => {
    const repository = new InMemoryConformanceSessionRepository();
    await repository.create({
      checks: [
        {
          description: 'PAR request contains a valid Wallet Attestation JWT',
          phase: 'ISSUANCE',
          requirementId: 'IT-WALLET-1.4-§4.2.1',
          result: 'PASS',
          step: 'PAR',
          timestamp: '2026-06-12T09:00:05.000Z'
        }
      ],
      sessionId: 'a1b2c3d4-0000-1111-2222-333344445555',
      startedAt: '2026-06-12T09:00:00.000Z',
      status: 'OPEN'
    });

    const result = await buildJsonReporterFromRepository(repository, 'a1b2c3d4-0000-1111-2222-333344445555', {
      now: new Date('2026-06-12T10:01:00.000Z'),
      ttlSeconds: 3600
    });

    expect(result).not.toBeNull();
    expect(result?.lazilyClosed).toBe(true);
    expect(result?.session.status).toBe('INCOMPLETE');
    expect(result?.jsonReporter.meta.status).toBe('INCOMPLETE');
  });

  it('keeps suites separated by phase when a session contains mixed phases', () => {
    const mixedSession: ConformanceSession = {
      checks: [
        {
          description: 'Wallet backend check',
          phase: 'WALLET_PROVIDER_BACKEND',
          requirementId: 'WP_001',
          result: 'PASS',
          step: 'WALLET_PROVIDER_BACKEND',
          timestamp: '2026-06-12T12:00:05.000Z'
        },
        {
          description: 'Presentation authorize check',
          phase: 'PRESENTATION',
          requirementId: 'PR_001',
          result: 'PASS',
          step: 'AUTHORIZE',
          timestamp: '2026-06-12T12:00:06.000Z'
        }
      ],
      sessionId: '123e4567-e89b-12d3-a456-426614174000',
      startedAt: '2026-06-12T12:00:00.000Z',
      status: 'PASSED'
    };

    const jsonReporter = buildJsonReporterFromSession(mixedSession);

    const walletSuite = jsonReporter.testResults.find(
      (suite) =>
        suite.name === 'WALLET_PROVIDER_BACKEND' && suite.assertionResults[0]?.meta.phase === 'WALLET_PROVIDER_BACKEND'
    );
    const presentationSuite = jsonReporter.testResults.find(
      (suite) => suite.name === 'AUTHORIZE' && suite.assertionResults[0]?.meta.phase === 'PRESENTATION'
    );

    const pendingPresentationSuite = jsonReporter.testResults.find(
      (suite) => suite.name === 'PRESENTATION_RESPONSE' && suite.assertionResults[0]?.meta.phase === 'PRESENTATION'
    );
    expect(pendingPresentationSuite?.status).toBe('pending');
    expect(pendingPresentationSuite?.assertionResults[0]?.meta.result).toBe('NOT_REACHED');

    expect(walletSuite).toBeDefined();
    expect(presentationSuite).toBeDefined();
    expect(walletSuite?.assertionResults.every((assertion) => assertion.meta.phase === 'WALLET_PROVIDER_BACKEND')).toBe(
      true
    );
    expect(presentationSuite?.assertionResults.every((assertion) => assertion.meta.phase === 'PRESENTATION')).toBe(
      true
    );
  });

  it('correctly infers WALLET_PROVIDER_BACKEND phase for wallet-backend-only sessions', () => {
    const session: ConformanceSession = {
      checks: [
        {
          description: 'Wallet Attestation is valid',
          phase: 'WALLET_PROVIDER_BACKEND',
          requirementId: 'WP_001',
          result: 'PASS',
          step: 'WALLET_PROVIDER_BACKEND',
          timestamp: '2026-06-12T12:00:05.000Z'
        }
      ],
      sessionId: 'aaaabbbb-0000-1111-2222-ccccddddeeee',
      startedAt: '2026-06-12T12:00:00.000Z',
      status: 'PASSED'
    };

    const jsonReporter = buildJsonReporterFromSession(session);

    expect(jsonReporter.numTotalTestSuites).toBe(1);
    expect(jsonReporter.numPassedTests).toBe(1);
    expect(jsonReporter.numPendingTests).toBe(0);

    const suite = jsonReporter.testResults[0];
    expect(suite?.name).toBe('WALLET_PROVIDER_BACKEND');
    expect(suite?.assertionResults[0]?.meta.phase).toBe('WALLET_PROVIDER_BACKEND');
    expect(suite?.assertionResults[0]?.ancestorTitles[0]).toBe('Wallet Provider Backend');
  });
});
