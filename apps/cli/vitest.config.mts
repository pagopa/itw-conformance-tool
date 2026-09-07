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
    reporters: ['default'],
    coverage: {
      reportsDirectory: './test-output/vitest/coverage',
      provider: 'v8' as const
    },
    server: {
      deps: {
        // Force @fastify/autoload to run inside Vitest's module system so that
        // its dynamic imports go through Vite's resolver and .js → .ts mapping
        // works. The federation certificate tests boot the real service apps,
        // which autoload their plugins and routes from source.
        inline: ['@fastify/autoload']
      }
    }
  }
}));
