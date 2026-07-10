import { expect } from 'vitest';

import type { ScenarioOutcome, ScenarioVerdict } from '../verdict/outcome.js';

export interface AssertConformanceOutcomeOptions {
  assertionMode?: 'report-only' | 'strict';
  expected: Extract<ScenarioVerdict, 'PASS'>;
}

export function assertConformanceOutcome(outcome: ScenarioOutcome, options: AssertConformanceOutcomeOptions): void {
  if (options.assertionMode === 'report-only') {
    expect(outcome.verdict).toBeDefined();
    return;
  }

  expect(outcome.verdict, outcome.reason).toBe(options.expected);
}
