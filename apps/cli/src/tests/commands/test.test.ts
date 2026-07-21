import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

import { test as runTestCommand } from '../../commands/test.js';

import type { EmitLog } from '../../types/types.js';

describe('test command', () => {
  const emitLog: EmitLog = vi.fn();
  const runtimeEnv: NodeJS.ProcessEnv = {
    ITW_CT_DATA_DIR: '/repo/.test-data',
    ITW_CT_WALLET_PROVIDER_BACKEND_URL: 'https://wallet.example'
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    // No explicit signal listener cleanup needed: runTestCommand registers `once` handlers and each test emits the signal.
  });

  it('resolves cleanly when SIGINT is received', async () => {
    const promise = runTestCommand(runtimeEnv, emitLog);
    process.emit('SIGINT', 'SIGINT');
    await expect(promise).resolves.toBeUndefined();
  });

  it('resolves cleanly when SIGTERM is received', async () => {
    const promise = runTestCommand(runtimeEnv, emitLog);
    process.emit('SIGTERM', 'SIGTERM');
    await expect(promise).resolves.toBeUndefined();
  });

  it('prints start and end messages', async () => {
    const promise = runTestCommand(runtimeEnv, emitLog);
    process.emit('SIGINT', 'SIGINT');
    await promise;

    expect(emitLog).toHaveBeenCalledWith(
      'Conformance test mode active. Make sure services are running via `itwct start --all`.',
      'info'
    );
    expect(emitLog).toHaveBeenCalledWith('Run wallet flows against the RP. Press Ctrl+C to stop.', 'info');
    expect(emitLog).toHaveBeenCalledWith(
      'Test session ended. Run `itwct report:list` to view captured sessions.',
      'info'
    );
  });
});
