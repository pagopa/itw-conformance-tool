import { existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { defineConfig } from 'vitest/config';

const packageRoot = import.meta.dirname;

const builtReporterPath = path.join(packageRoot, 'packages/conformance/dist/report/reporter.js');
const sourceReporterPath = path.join(packageRoot, 'packages/conformance/src/report/reporter.ts');
const reporterModulePath = existsSync(builtReporterPath) ? builtReporterPath : sourceReporterPath;
const { ConformanceReporter } = await import(pathToFileURL(reporterModulePath).href);

const conformanceTestCategory = process.env.ITWCT_CONFORMANCE_TEST_CATEGORY;
if (
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
    reporters: ['dot', new ConformanceReporter(conformanceTestCategory)],
    // node:sqlite requires --experimental-sqlite on Node.js 22.
    pool: 'forks',
    forks: {
      execArgv: ['--experimental-sqlite']
    }
  }
}));
