import { vi } from 'vitest';

// Mocks for utils/search.ts
export const findRoot = vi.fn(() => '/root');
export const searchNx = vi.fn(() => '/root/node_modules/nx/dist/bin/nx.js');
export const expandPath = vi.fn((path: string) => path);
export const createFileDirPaths = vi.fn<(filePath: string, httpsEnabled?: boolean) => string[]>(() => []);
export const existsFileSync = vi.fn(() => true);

// Vi mocks
vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
  statSync: vi.fn(),
  readFileSync: vi.fn(),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn()
}));
