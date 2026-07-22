import { randomUUID } from 'node:crypto';

import { loadConfig } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { logger } from '@itw-conformance-tool/logger';

import { appendCheck, closeSession, createSession } from './session-store.js';

import type { ConformanceCheck, Phase } from './types.js';
import type { TestResult } from 'vitest/node';
import type { Reporter } from 'vitest/reporters';

type CheckResult = ConformanceCheck['result'];

type ReporterTestCase = Parameters<NonNullable<Reporter['onTestCaseResult']>>[0];

type SessionStatus = 'FAILED' | 'INCOMPLETE' | 'PASSED';
type TestType = Phase;

// Example IT Wallet Test Matrix IDs -> WP_001
const REQUIREMENT_ID_PATTERN = /^([A-Z]+[_]\d+\w*)\s*:/;
const DEFAULT_ENTITY_NAME = '-';

export class ConformanceReporter implements Reporter {
  private checkResults: CheckResult[] = [];
  private db: DatabaseClient;
  private sessionId: string | undefined;
  private readonly testType: TestType;

  constructor(testType: TestType) {
    const config = loadConfig();
    this.db = new DatabaseClient(config.global.data_dir);
    this.testType = testType;
  }

  onTestCaseResult(testCase: ReporterTestCase): void {
    if (!this.sessionId) {
      return;
    }

    const title = testCase.name;
    const result = this.mapResult(testCase.result().state);
    const check: ConformanceCheck = {
      description: this.parseTestCaseName(title),
      phase: this.testType,
      requirementId: this.parseRequirementId(title),
      result,
      timestamp: new Date().toISOString()
    };

    if (result === 'FAIL') {
      check.errorMessage = this.extractFailureMessage(testCase);
    }

    appendCheck(this.db, this.sessionId, check);
    this.checkResults.push(result);
  }

  onTestRunEnd(): void {
    if (!this.sessionId) {
      return;
    }

    const status = this.resolveFinalStatus(this.checkResults);
    closeSession(this.db, this.sessionId, status, new Date().toISOString());
    this.db.close();

    logger.info(`Conformance session ID: ${this.sessionId}`);
  }

  onTestRunStart(): void {
    this.sessionId = randomUUID();
    this.checkResults = [];

    createSession(this.db, {
      entityName: DEFAULT_ENTITY_NAME,
      id: this.sessionId,
      phase: this.testType,
      startedAt: new Date().toISOString(),
      status: 'OPEN'
    });
  }

  private extractFailureMessage(testCase: ReporterTestCase): string {
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

  private mapResult(state: TestResult['state']): CheckResult {
    if (state === 'passed') {
      return 'PASS';
    }

    if (state === 'failed') {
      return 'FAIL';
    }

    return 'NOT_REACHED';
  }

  private parseRequirementId(title: string): string {
    const requirement = REQUIREMENT_ID_PATTERN.exec(title)?.[1];
    return requirement ?? title;
  }

  private parseTestCaseName(name: string): string {
    return name.replace(REQUIREMENT_ID_PATTERN, '').trim();
  }

  private resolveFinalStatus(results: readonly CheckResult[]): SessionStatus {
    if (results.includes('FAIL')) {
      return 'FAILED';
    }

    if (results.includes('NOT_REACHED')) {
      return 'INCOMPLETE';
    }

    return 'PASSED';
  }
}
