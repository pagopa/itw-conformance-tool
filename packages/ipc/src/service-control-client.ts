import { randomUUID } from 'node:crypto';
import net from 'node:net';

import { parseIpcMessage } from './messages.js';
import { SERVICE_PROTOCOL_VERSION } from './protocol.js';

import type { IpcMessage } from './messages.js';
import type {
  IssuerConfigActivationRequest,
  IssuerConfigDeactivationRequest,
  IssuerFaultActivationRequest,
  IssuerFaultDeactivationRequest
} from './service-adapter.js';

const DEFAULT_TIMEOUT_MS = 15_000;
const FRAME_DELIMITER = '\n';

export interface ServiceControlClientOptions {
  /** Unix domain socket path (POSIX) or named pipe path (Windows). */
  endpoint: string;
  /** Bounded timeout applied to every request/response round-trip. */
  timeoutMs?: number;
}

export interface ServiceControlClient {
  activateIssuerConfig(request: IssuerConfigActivationRequest): Promise<void>;
  deactivateIssuerConfig(request: IssuerConfigDeactivationRequest): Promise<void>;
  activateIssuerFault(request: IssuerFaultActivationRequest): Promise<void>;
  deactivateIssuerFault(request: IssuerFaultDeactivationRequest): Promise<void>;
  close(): Promise<void>;
}

interface PendingRequest {
  resolve: () => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

/**
 * Creates a client for the CLI-owned local control relay. It connects to a
 * process-local Unix socket / named pipe, frames requests as newline-delimited
 * JSON, and correlates responses by request ID with a bounded timeout. Never
 * logs raw fault payloads.
 */
export function createServiceControlClient(options: ServiceControlClientOptions): ServiceControlClient {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pending = new Map<string, PendingRequest>();
  let buffer = '';

  const socket = net.createConnection(options.endpoint);
  socket.setEncoding('utf8');

  const connected = new Promise<void>((resolve, reject) => {
    socket.once('connect', resolve);
    socket.once('error', reject);
  });

  const failAllPending = (error: Error): void => {
    for (const [requestId, request] of pending) {
      clearTimeout(request.timeout);
      request.reject(error);
      pending.delete(requestId);
    }
  };

  socket.on('data', (chunk: string) => {
    buffer += chunk;
    let newlineIndex = buffer.indexOf(FRAME_DELIMITER);
    while (newlineIndex !== -1) {
      const frame = buffer.slice(0, newlineIndex);
      buffer = buffer.slice(newlineIndex + 1);
      newlineIndex = buffer.indexOf(FRAME_DELIMITER);
      handleFrame(frame);
    }
  });

  socket.on('error', (error) => failAllPending(error instanceof Error ? error : new Error(String(error))));
  socket.on('close', () => failAllPending(new Error('Service control connection closed')));

  function handleFrame(frame: string): void {
    if (!frame) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(frame);
    } catch {
      return;
    }

    const message = parseIpcMessage(parsed);
    if (!message || message.version !== SERVICE_PROTOCOL_VERSION) return;
    resolvePending(message);
  }

  function resolvePending(message: IpcMessage): void {
    if (!('requestId' in message) || typeof message.requestId !== 'string') return;
    const request = pending.get(message.requestId);
    if (!request) return;

    if (
      message.type === 'issuer.fault.activated' ||
      message.type === 'issuer.fault.deactivated' ||
      message.type === 'issuer.config.activated' ||
      message.type === 'issuer.config.deactivated'
    ) {
      clearTimeout(request.timeout);
      pending.delete(message.requestId);
      request.resolve();
      return;
    }

    if (message.type === 'service.error') {
      clearTimeout(request.timeout);
      pending.delete(message.requestId);
      request.reject(new Error(`Service control request failed: ${message.code}`));
    }
  }

  async function send(message: IpcMessage, requestId: string): Promise<void> {
    await connected;
    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        pending.delete(requestId);
        reject(new Error(`Timed out waiting for a response to ${message.type}`));
      }, timeoutMs);

      pending.set(requestId, { resolve, reject, timeout });
      socket.write(`${JSON.stringify(message)}${FRAME_DELIMITER}`, (error) => {
        if (!error) return;
        clearTimeout(timeout);
        pending.delete(requestId);
        reject(error);
      });
    });
  }

  return {
    async activateIssuerConfig(request: IssuerConfigActivationRequest): Promise<void> {
      const requestId = randomUUID();
      await send(
        {
          version: SERVICE_PROTOCOL_VERSION,
          type: 'issuer.config.activate',
          requestId,
          scenarioId: request.scenarioId,
          config: request.config
        },
        requestId
      );
    },

    async deactivateIssuerConfig(request: IssuerConfigDeactivationRequest): Promise<void> {
      const requestId = randomUUID();
      await send(
        {
          version: SERVICE_PROTOCOL_VERSION,
          type: 'issuer.config.deactivate',
          requestId,
          scenarioId: request.scenarioId
        },
        requestId
      );
    },

    async activateIssuerFault(request: IssuerFaultActivationRequest): Promise<void> {
      const requestId = randomUUID();
      await send(
        {
          version: SERVICE_PROTOCOL_VERSION,
          type: 'issuer.fault.activate',
          requestId,
          scenarioId: request.scenarioId,
          specVersion: request.specVersion,
          profile: request.profile
        },
        requestId
      );
    },

    async deactivateIssuerFault(request: IssuerFaultDeactivationRequest): Promise<void> {
      const requestId = randomUUID();
      await send(
        {
          version: SERVICE_PROTOCOL_VERSION,
          type: 'issuer.fault.deactivate',
          requestId,
          scenarioId: request.scenarioId
        },
        requestId
      );
    },

    async close(): Promise<void> {
      failAllPending(new Error('Service control client closed'));
      await new Promise<void>((resolve) => socket.end(() => resolve()));
    }
  };
}
