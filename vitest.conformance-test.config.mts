import { resolve } from 'node:path';

import { defineConfig } from 'vitest/config';

import { VitestConformanceReporter } from './packages/conformance/src/reporters/vitest-conformance-reporter.js';

const packageRoot = import.meta.dirname;

export default defineConfig(() => ({
  root: packageRoot,
  cacheDir: './node_modules/.vite/packages/conformance-test',
  resolve: {
    alias: {
      '@itw-conformance-tool/database': resolve(packageRoot, './packages/database/src/index.ts')
    }
  },
  test: {
    name: '@itw-conformance-tool/conformance-test',
    watch: false,
    passWithNoTests: true,
    globals: true,
    environment: 'node',
    include: ['packages/conformance/src/tests/matrix/**/*.test.ts'],
    reporters: ['dot', new VitestConformanceReporter('conformance-test')],
    // node:sqlite requires --experimental-sqlite on Node.js 22.
    pool: 'forks',
    forks: {
      execArgv: ['--experimental-sqlite']
    }
  }
}));
