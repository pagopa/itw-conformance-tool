import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';

import { describe, it, expect, vi, beforeEach } from 'vitest';

import { runCommands } from '../../services/runCommands.js';

import type { EmitLog, ServiceProcess } from '../../types/types.js';

const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }));

vi.mock('node:child_process', () => ({
  spawn: spawnMock
}));

vi.mock('../../utils/search.js', () => ({
  searchNx: vi.fn(() => '/nx/cli.js')
}));

function makeChild() {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const kill = vi.fn();
  const child = Object.assign(new EventEmitter(), { stdout, stderr, kill });
  return { child, stdout, stderr, kill };
}

function nextTick(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

const ISSUER: ServiceProcess = { prefix: 'itw-credential-issuer', nxArgs: ['run', 'itw-credential-issuer:serve'] };
const RP: ServiceProcess = { prefix: 'itw-relying-party', nxArgs: ['run', 'itw-relying-party:serve'] };

describe('runCommands', () => {
  let emitLog: EmitLog;

  beforeEach(() => {
    vi.clearAllMocks();
    emitLog = vi.fn();
  });

  describe('exit code handling', () => {
    it('resolves with 0 when a single service exits cleanly', async () => {
      const { child } = makeChild();
      spawnMock.mockReturnValueOnce(child);

      const promise = runCommands('/root', [ISSUER], {}, emitLog);
      child.emit('close', 0);

      await expect(promise).resolves.toBe(0);
    });

    it('resolves with 0 when all services exit cleanly', async () => {
      const { child: child1 } = makeChild();
      const { child: child2 } = makeChild();
      spawnMock.mockReturnValueOnce(child1).mockReturnValueOnce(child2);

      const promise = runCommands('/root', [ISSUER, RP], {}, emitLog);
      child1.emit('close', 0);
      child2.emit('close', 0);

      await expect(promise).resolves.toBe(0);
    });

    it('resolves with the non-zero exit code when a service fails', async () => {
      const { child } = makeChild();
      spawnMock.mockReturnValueOnce(child);

      const promise = runCommands('/root', [ISSUER], {}, emitLog);
      child.emit('close', 2);

      await expect(promise).resolves.toBe(2);
    });

    it('resolves with 1 when close code is null (process killed by signal)', async () => {
      const { child } = makeChild();
      spawnMock.mockReturnValueOnce(child);

      const promise = runCommands('/root', [ISSUER], {}, emitLog);
      child.emit('close', null);

      await expect(promise).resolves.toBe(1);
    });
  });

  describe('fail-fast behavior', () => {
    it('kills remaining children when one service exits with non-zero code', async () => {
      const { child: child1 } = makeChild();
      const { child: child2, kill: kill2 } = makeChild();
      spawnMock.mockReturnValueOnce(child1).mockReturnValueOnce(child2);

      const promise = runCommands('/root', [ISSUER, RP], {}, emitLog);
      child1.emit('close', 1);
      await promise;

      expect(kill2).toHaveBeenCalled();
    });

    it('resolves with the failing exit code in a multi-service setup', async () => {
      const { child: child1 } = makeChild();
      const { child: child2 } = makeChild();
      spawnMock.mockReturnValueOnce(child1).mockReturnValueOnce(child2);

      const promise = runCommands('/root', [ISSUER, RP], {}, emitLog);
      child1.emit('close', 3);

      await expect(promise).resolves.toBe(3);
    });

    it('does not kill other children when all services exit cleanly', async () => {
      const { child: child1 } = makeChild();
      const { child: child2, kill: kill2 } = makeChild();
      spawnMock.mockReturnValueOnce(child1).mockReturnValueOnce(child2);

      const promise = runCommands('/root', [ISSUER, RP], {}, emitLog);
      child1.emit('close', 0);
      child2.emit('close', 0);
      await promise;

      expect(kill2).not.toHaveBeenCalled();
    });
  });

  describe('output prefixing', () => {
    it('emits stdout lines prefixed with [prefix] at info level', async () => {
      const { child, stdout } = makeChild();
      spawnMock.mockReturnValueOnce(child);

      const promise = runCommands('/root', [ISSUER], {}, emitLog);

      stdout.end('server started\n');
      await nextTick();

      child.emit('close', 0);
      await promise;

      expect(emitLog).toHaveBeenCalledWith('[itw-credential-issuer] server started', 'info');
    });

    it('emits stderr lines prefixed with [prefix] at error level', async () => {
      const { child, stderr } = makeChild();
      spawnMock.mockReturnValueOnce(child);

      const promise = runCommands('/root', [ISSUER], {}, emitLog);

      stderr.end('something went wrong\n');
      await nextTick();

      child.emit('close', 1);
      await promise;

      expect(emitLog).toHaveBeenCalledWith('[itw-credential-issuer] something went wrong', 'error');
    });

    it('prefixes output from multiple services with correct service names', async () => {
      const { child: child1, stdout: stdout1 } = makeChild();
      const { child: child2, stdout: stdout2 } = makeChild();
      spawnMock.mockReturnValueOnce(child1).mockReturnValueOnce(child2);

      const promise = runCommands('/root', [ISSUER, RP], {}, emitLog);

      stdout1.end('issuer log\n');
      stdout2.end('rp log\n');
      await nextTick();

      child1.emit('close', 0);
      child2.emit('close', 0);
      await promise;

      expect(emitLog).toHaveBeenCalledWith('[itw-credential-issuer] issuer log', 'info');
      expect(emitLog).toHaveBeenCalledWith('[itw-relying-party] rp log', 'info');
    });
  });

  describe('process error handling', () => {
    it('resolves with 1 and logs the error when a child emits an error event', async () => {
      const { child } = makeChild();
      spawnMock.mockReturnValueOnce(child);

      const promise = runCommands('/root', [ISSUER], {}, emitLog);
      child.emit('error', new Error('ENOENT'));

      await expect(promise).resolves.toBe(1);
      expect(emitLog).toHaveBeenCalledWith(expect.stringContaining('[itw-credential-issuer]'), 'error');
    });
  });
});
