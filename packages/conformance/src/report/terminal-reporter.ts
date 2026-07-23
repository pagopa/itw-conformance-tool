import { basename } from 'node:path';

import { testCategoryByFileName } from '@itw-conformance-tool/utils';
import chalk from 'chalk';

import type { Reporter } from 'vitest/reporters';

type ReporterTestCase = Parameters<NonNullable<Reporter['onTestCaseResult']>>[0];
type ReporterTestModule = Parameters<NonNullable<Reporter['onTestModuleStart']>>[0];

type TerminalWrite = (message: string) => void;

const RESULT_SEPARATOR = chalk.dim('·');
const REQUIREMENT_ID_PATTERN = /^\[?([A-Z]+_\d+\w*)\]?\s*:\s*/;

export class TerminalConformanceReporter implements Reporter {
  private hasPrintedModule = false;
  private readonly write: TerminalWrite;

  constructor(write: TerminalWrite = (message) => process.stdout.write(`${message}\n`)) {
    this.write = write;
  }

  onTestModuleStart(testModule: ReporterTestModule): void {
    const title = getModuleTitle(testModule);
    if (!title) {
      return;
    }

    if (this.hasPrintedModule) {
      this.write('');
    }
    this.hasPrintedModule = true;

    this.write(chalk.bold.cyan(`▸ ${title}`));
  }

  onTestModuleEnd(testModule: ReporterTestModule): void {
    if (getModuleTitle(testModule) && Array.from(testModule.children.allTests()).length === 0) {
      this.write(chalk.yellow('No executable tests are defined for this category.'));
    }
  }

  onTestCaseResult(testCase: ReporterTestCase): void {
    const result = testCase.result();
    const duration = formatDuration(testCase.diagnostic()?.duration);

    const { requirementId, title } = parseTestTitle(testCase.name);
    const outcome = formatOutcome(result.state);
    this.write(`${outcome} ${chalk.bold(requirementId)} ${title} ${RESULT_SEPARATOR} ${duration}`);

    if (result.state === 'failed') {
      for (const line of formatFailureMessage(extractFailureMessage(result.errors[0]))) {
        this.write(line);
      }
    }
  }
}

function formatOutcome(state: 'passed' | 'failed' | 'skipped' | 'pending'): string {
  if (state === 'passed') return chalk.green('✓');
  if (state === 'failed') return chalk.red('✗');
  return chalk.yellow('○');
}

function formatFailureMessage(message: string): string[] {
  return message.split('\n').map((line) => chalk.red(`  ↳ ${line}`));
}

function getModuleTitle(testModule: ReporterTestModule): string | undefined {
  return testCategoryByFileName[basename(testModule.moduleId) as keyof typeof testCategoryByFileName]?.title;
}

function extractFailureMessage(error: unknown): string {
  if (typeof error === 'string') {
    return error;
  }

  if (typeof error === 'object' && error !== null && 'message' in error) {
    const { message } = error;
    if (typeof message === 'string' && message.length > 0) {
      return message;
    }
  }

  return 'Test failed without error details';
}

function formatDuration(duration: number | undefined): string {
  if (duration === undefined) return 'duration unavailable';
  if (duration < 1_000) return `${Math.round(duration)} ms`;
  return `${(duration / 1_000).toFixed(1)} s`;
}

function parseTestTitle(name: string): { requirementId: string; title: string } {
  const match = REQUIREMENT_ID_PATTERN.exec(name);
  if (!match) {
    return { requirementId: 'TEST', title: name };
  }

  return { requirementId: match[1], title: name.slice(match[0].length) };
}
