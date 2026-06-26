import { resolve } from 'node:path';

import { defineConfig } from 'vitest/config';

export default defineConfig(() => ({
  root: import.meta.dirname,
  cacheDir: '../../node_modules/.vite/packages/conformance',
  resolve: {
    alias: {
      '@itw-conformance-tool/database': resolve(import.meta.dirname, '../../packages/database/src/index.ts')
    }
  },
  test: {
    name: '@itw-conformance-tool/conformance',
    watch: false,
    globals: true,
    environment: 'node',
    include: ['src/**/*.{test,spec}.ts', 'src/__tests__/**/*.ts'],
    exclude: ['src/tests/matrix/**', '**/node_modules/**', '**/.git/**'],
    reporters: ['default'],
    // node:sqlite requires --experimental-sqlite on Node.js 22
    pool: 'forks',
    forks: {
      execArgv: ['--experimental-sqlite']
    },
    coverage: {
      reportsDirectory: './test-output/vitest/coverage',
      provider: 'v8' as const,
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80
      }
    }
  }
}));
