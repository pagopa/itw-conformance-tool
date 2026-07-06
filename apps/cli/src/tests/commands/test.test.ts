import { EventEmitter } from 'node:events';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { test as runTestCommand } from '../../commands/test.js';

import type { EmitLog } from '../../types/types.js';

const { spawnMock } = vi.hoisted(() => ({
  spawnMock: vi.fn(),
  closeMock: vi.fn(),
  getMock: vi.fn(),
  prepareMock: vi.fn()
}));

vi.mock('node:child_process', () => ({
  spawn: spawnMock
}));

vi.mock('../../utils/search.js', () => ({
  findNxRoot: vi.fn(() => '/repo')
}));

function makeChild(exitCode: number): EventEmitter {
  const child = new EventEmitter();
  queueMicrotask(() => child.emit('close', exitCode));
  return child;
}

describe('test command', () => {
  const emitLog: EmitLog = vi.fn();
  const runtimeEnv: NodeJS.ProcessEnv = {
    ITW_CT_DATA_DIR: '/repo/.test-data',
    ITW_CT_WALLET_PROVIDER_BACKEND_URL: 'https://wallet.example'
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('runs vitest with conformance config and forwards runtime env', async () => {
    spawnMock.mockReturnValue(makeChild(0));

    await runTestCommand(runtimeEnv, emitLog);

    expect(spawnMock).toHaveBeenCalledWith(
      'pnpm',
      ['vitest', 'run', '--config', '/repo/vitest.conformance-test.config.mts'],
      expect.objectContaining({
        cwd: '/repo',
        stdio: 'inherit',
        env: expect.objectContaining({
          ITW_CT_DATA_DIR: '/repo/.test-data',
          ITW_CT_WALLET_PROVIDER_BACKEND_URL: 'https://wallet.example'
        })
      })
    );
    expect(emitLog).toHaveBeenCalledWith('Conformance tests completed', 'info');
  });

  it('surfaces Vitest failures without emitting completion log', async () => {
    spawnMock.mockReturnValue(makeChild(1));

    await expect(runTestCommand(runtimeEnv, emitLog)).rejects.toThrow('Conformance tests failed with exit code 1');

    expect(emitLog).not.toHaveBeenCalledWith('Conformance tests completed', 'info');
  });
});
