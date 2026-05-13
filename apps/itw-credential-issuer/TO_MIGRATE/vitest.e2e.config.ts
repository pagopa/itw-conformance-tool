import * as path from 'node:path';
import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src')
    }
  },
  test: {
    environment: 'node',
    exclude: configDefaults.exclude,
    globalSetup: ['./tests/globalSetup.ts'],
    include: ['**/*.e2e.spec.ts']
  }
});
