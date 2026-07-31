import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { defineConfig } from 'vitest/config';
import { BaseSequencer, type TestSpecification } from 'vitest/node';

const packageRoot = import.meta.dirname;

const matrixTestOrder: Readonly<Record<string, number>> = {
  'wallet-provider.test.ts': 0,
  'wallet-instance.test.ts': 1,
  'issuance.test.ts': 2,
  'presentation.test.ts': 3
};

function getTestOrder(file: TestSpecification): number {
  const fileName = path.basename(file.moduleId);
  const configuredOrder = matrixTestOrder[fileName];

  return configuredOrder ?? Number.MAX_SAFE_INTEGER;
}

class MatrixSequencer extends BaseSequencer {
  async sort(files: TestSpecification[]): Promise<TestSpecification[]> {
    return [...files].sort((left, right) => {
      const orderDifference = getTestOrder(left) - getTestOrder(right);

      return orderDifference || left.moduleId.localeCompare(right.moduleId);
    });
  }
}

const reporterModulePath = path.join(packageRoot, 'packages/conformance/dist/report/reporter.js');
const { ConformanceReporter } = await import(pathToFileURL(reporterModulePath).href);

const conformanceTestCategory = process.env.ITWCT_CONFORMANCE_TEST_CATEGORY ?? 'all';
const conformanceVerbose = process.env.ITWCT_CONFORMANCE_VERBOSE === '1';
if (
  conformanceTestCategory !== 'all' &&
  conformanceTestCategory !== 'issuance' &&
  conformanceTestCategory !== 'presentation' &&
  conformanceTestCategory !== 'wallet-instance' &&
  conformanceTestCategory !== 'wallet-provider'
) {
  throw new Error(
    'ITWCT_CONFORMANCE_TEST_CATEGORY must be one of: issuance, presentation, wallet-instance, wallet-provider.'
  );
}

export default defineConfig(() => ({
  root: packageRoot,
  cacheDir: path.join(packageRoot, 'node_modules/.vitest'),
  test: {
    name: '@itw-conformance-tool/conformance',
    watch: false,
    passWithNoTests: true,
    globals: true,
    environment: 'node',
    include: ['packages/conformance/src/tests/matrix/**/*.test.ts'],
    fileParallelism: false,
    sequence: { sequencer: MatrixSequencer },
    reporters: [
      conformanceVerbose ? 'tree' : ['default', { summary: false }],
      new ConformanceReporter(conformanceTestCategory)
    ],
    // node:sqlite requires --experimental-sqlite on Node.js 22.
    pool: 'forks',
    forks: {
      execArgv: ['--experimental-sqlite']
    }
  }
}));
