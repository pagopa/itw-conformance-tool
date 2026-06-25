import { defineConfig } from 'vitest/config';

export default defineConfig(() => ({
  root: import.meta.dirname,
  cacheDir: '../../node_modules/.vite/apps/cli-conformance',
  test: {
    name: 'itw-conformance-cli-conformance',
    watch: false,
    passWithNoTests: true,
    globals: true,
    environment: 'node',
    include: ['src/tests/conformance/**/*.{test,spec}.ts'],
    setupFiles: ['./src/tests/setup.test.ts'],
    reporters: ['default']
  }
}));
