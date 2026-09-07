import { fork, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';

import {
  parseIpcMessage,
  SERVICE_PROTOCOL_VERSION,
  type IpcMessage,
  type LocalServiceName,
  type ServiceErrorMessage
} from '@itw-conformance-tool/ipc';

export type SupervisedService = LocalServiceName;
export type SupervisedEndpoints = Partial<Record<SupervisedService, string>>;

export interface ServiceSupervisorOptions {
  cwd: string;
  env?: NodeJS.ProcessEnv;
  readinessTimeoutMs?: number;
  shutdownTimeoutMs?: number;
}

interface ManagedService {
  child: ChildProcess;
  endpoint?: string;
  service: SupervisedService;
}

const require = createRequire(import.meta.url);

function resolveServiceEntrypoint(service: SupervisedService): string {
  const packageName = `itw-${service}`;

  try {
    return require.resolve(packageName);
  } catch {
    throw new Error(`Cannot resolve the ${service} package (${packageName}). Run \`pnpm install\` first.`);
  }
}

function waitForExit(child: ChildProcess, timeoutMs: number): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const timeout = setTimeout(resolve, timeoutMs);
    child.once('exit', () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

/** Owns child service processes for one CLI test invocation. */
export class ServiceSupervisor {
  private readonly managed = new Map<SupervisedService, ManagedService>();
  private readonly options: ServiceSupervisorOptions;
  private readonly readinessTimeoutMs: number;
  private readonly shutdownTimeoutMs: number;

  public constructor(options: ServiceSupervisorOptions) {
    this.options = options;
    this.readinessTimeoutMs = options.readinessTimeoutMs ?? 30_000;
    this.shutdownTimeoutMs = options.shutdownTimeoutMs ?? 10_000;
  }

  public async start(services: readonly SupervisedService[]): Promise<SupervisedEndpoints> {
    try {
      await Promise.all(services.map((service) => this.startOne(service)));
      return Object.fromEntries([...this.managed].map(([service, managed]) => [service, managed.endpoint]));
    } catch (error) {
      await this.stopAll();
      throw error;
    }
  }

  public async stopAll(): Promise<void> {
    await Promise.all([...this.managed.values()].map((managed) => this.stopOne(managed)));
    this.managed.clear();
  }

  /**
   * Forwards one IPC message to a managed child's process channel. Returns
   * `false` without throwing if the service is not currently managed or has
   * already exited, so callers can surface an explicit control-plane error.
   */
  public sendToChild(service: SupervisedService, message: IpcMessage): boolean {
    const managed = this.managed.get(service);
    if (!managed || managed.child.exitCode !== null || managed.child.signalCode !== null) return false;
    managed.child.send(message);
    return true;
  }

  /**
   * Subscribes to validated IPC messages from a managed child. Returns an
   * unsubscribe function. Messages that fail schema validation are dropped
   * silently, matching the rest of the IPC transport.
   */
  public onChildMessage(service: SupervisedService, listener: (message: IpcMessage) => void): () => void {
    const managed = this.managed.get(service);
    if (!managed) return () => undefined;

    const handler = (rawMessage: unknown): void => {
      const message = parseIpcMessage(rawMessage);
      if (message) listener(message);
    };

    managed.child.on('message', handler);
    return () => managed.child.off('message', handler);
  }

  private async startOne(service: SupervisedService): Promise<void> {
    if (this.managed.has(service)) return;
    const entrypoint = resolveServiceEntrypoint(service);
    if (!existsSync(entrypoint)) {
      throw new Error(`Missing compiled ${service} entrypoint: ${entrypoint}. Run \`pnpm build\` first.`);
    }

    const child = fork(entrypoint, [], {
      cwd: this.options.cwd,
      detached: process.platform !== 'win32',
      env: this.options.env ?? process.env,
      silent: false
    });

    const managed: ManagedService = { child, service };
    this.managed.set(service, managed);

    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error(`Timed out waiting for ${service} readiness`)),
        this.readinessTimeoutMs
      );

      const fail = (reason: Error): void => {
        clearTimeout(timeout);
        reject(reason);
      };

      child.once('error', (error) => fail(new Error(`${service} failed to start: ${error.message}`)));
      child.once('exit', (code, signal) => {
        if (!managed.endpoint) fail(new Error(`${service} exited before readiness (code=${code}, signal=${signal})`));
      });

      child.on('message', (rawMessage) => {
        const message = parseIpcMessage(rawMessage);
        if (!message) return;
        if (message.type === 'service.ready' && message.service === service) {
          clearTimeout(timeout);
          managed.endpoint = message.endpoint;
          resolve();
        }
        if (message.type === 'service.error') {
          const error = message as ServiceErrorMessage;
          fail(new Error(`${service} IPC error ${error.code}: ${error.message}`));
        }
      });
    });
  }

  private async stopOne(managed: ManagedService): Promise<void> {
    const { child, service } = managed;
    if (child.exitCode !== null || child.signalCode !== null) return;

    const requestId = randomUUID();

    const stopped = new Promise<void>((resolve) => {
      child.on('message', (rawMessage) => {
        const message = parseIpcMessage(rawMessage);
        if (
          message?.type === 'service.stopped' &&
          message.requestId === requestId &&
          message.service === service &&
          message.version === SERVICE_PROTOCOL_VERSION
        ) {
          resolve();
        }
      });
    });

    child.send({ version: SERVICE_PROTOCOL_VERSION, type: 'service.stop', requestId });

    await Promise.race([stopped, waitForExit(child, this.shutdownTimeoutMs)]);

    if (child.exitCode === null && child.signalCode === null) this.kill(child, 'SIGTERM');
    await waitForExit(child, this.shutdownTimeoutMs);

    if (child.exitCode === null && child.signalCode === null) this.kill(child, 'SIGKILL');
  }

  private kill(child: ChildProcess, signal: NodeJS.Signals): void {
    try {
      if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal);
      else child.kill(signal);
    } catch {
      // The process may have exited between the state check and kill.
    }
  }
}
