import { defineConfig } from 'vitest/config';

export default defineConfig(() => ({
  root: import.meta.dirname,
  cacheDir: '../../node_modules/.vite/apps/itw-credential-issuer',
  test: {
    name: 'itw-credential-issuer',
    watch: false,
    passWithNoTests: true,
    globals: true,
    environment: 'node',
    include: ['{src,tests}/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    reporters: ['default'],
    coverage: {
      reportsDirectory: './test-output/vitest/coverage',
      provider: 'v8' as const
    },
    server: {
      deps: {
        // Force @fastify/autoload to run inside Vitest's module system so that
        // its dynamic imports go through Vite's resolver and .js → .ts mapping works.
        inline: ['@fastify/autoload']
      }
    }
  }
}));
