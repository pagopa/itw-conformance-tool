import { defineConfig } from 'vitest/config';

export default defineConfig(() => ({
  root: import.meta.dirname,
  cacheDir: '../../node_modules/.vite/apps/cli',
  test: {
    name: 'itw-conformance-cli',
    watch: false,
    passWithNoTests: true,
    globals: true,
    environment: 'node',
    include: ['src/tests/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    exclude: ['src/tests/conformance/**', '**/node_modules/**', '**/.git/**'],
    setupFiles: ['./src/tests/setup.test.ts'],
    reporters: ['default'],
    coverage: {
      reportsDirectory: './test-output/vitest/coverage',
      provider: 'v8' as const
    }
  }
}));
