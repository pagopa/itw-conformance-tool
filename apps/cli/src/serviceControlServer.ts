import { randomUUID } from 'node:crypto';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { parseIpcMessage, SERVICE_PROTOCOL_VERSION } from '@itw-conformance-tool/ipc';

import type { ServiceSupervisor, SupervisedService } from './supervisor.js';
import type { IpcMessage } from '@itw-conformance-tool/ipc';

const FRAME_DELIMITER = '\n';
const MAX_FRAME_BYTES = 64 * 1024;
const CHILD_RESPONSE_TIMEOUT_MS = 15_000;

export interface ServiceControlServerOptions {
  supervisor: ServiceSupervisor;
}

export interface ServiceControlServer {
  /** Unix socket path (POSIX) or named pipe path (Windows) to pass to the runner. */
  endpoint: string;
  close: () => Promise<void>;
}

interface PendingChildResponse {
  socket: net.Socket;
  timeout: NodeJS.Timeout;
}

/** Control requests the relay forwards, and the child that owns each of them. */
const CONTROL_REQUEST_TARGETS = {
  'issuer.config.activate': 'credential-issuer',
  'issuer.config.deactivate': 'credential-issuer',
  'issuer.fault.activate': 'credential-issuer',
  'issuer.fault.deactivate': 'credential-issuer',
  'rp.fault.activate': 'relying-party',
  'rp.fault.deactivate': 'relying-party'
} as const satisfies Partial<Record<IpcMessage['type'], SupervisedService>>;

type ControlRequestType = keyof typeof CONTROL_REQUEST_TARGETS;

/** Acknowledgements (plus errors) the relay correlates back to the caller. */
const CONTROL_RESPONSE_TYPES = [
  'issuer.config.activated',
  'issuer.config.deactivated',
  'issuer.fault.activated',
  'issuer.fault.deactivated',
  'rp.fault.activated',
  'rp.fault.deactivated',
  'service.error'
] as const satisfies readonly IpcMessage['type'][];

function isControlRequest(message: IpcMessage): message is IpcMessage & { type: ControlRequestType } {
  return message.type in CONTROL_REQUEST_TARGETS;
}

function isControlResponse(message: IpcMessage): boolean {
  return (CONTROL_RESPONSE_TYPES as readonly string[]).includes(message.type);
}

function writeFrame(socket: net.Socket, message: IpcMessage): void {
  if (socket.writable) socket.write(`${JSON.stringify(message)}${FRAME_DELIMITER}`);
}

async function allocateEndpoint(): Promise<string> {
  if (process.platform === 'win32') {
    return `\\\\.\\pipe\\itwct-control-${randomUUID()}`;
  }

  const dir = await mkdtemp(path.join(tmpdir(), `itwct-control-}`));
  await chmod(dir, 0o700);
  return path.join(dir, 'control.sock');
}

/**
 * Local-only control relay between the Vitest conformance runner process and
 * the CLI-owned service children. Only fault/config control messages are
 * relayed, and only to the managed child that owns each message type (see
 * `CONTROL_REQUEST_TARGETS`). This is never exposed as an HTTP route, uses a
 * random endpoint in a private temporary directory, owner-only permissions
 * where supported, newline-delimited framing, bounded frame sizes, and
 * request-ID correlation.
 */
export async function startServiceControlServer(options: ServiceControlServerOptions): Promise<ServiceControlServer> {
  const endpoint = await allocateEndpoint();
  const pendingByRequestId = new Map<string, PendingChildResponse>();

  const relayedServices = [...new Set(Object.values(CONTROL_REQUEST_TARGETS))];
  const unsubscribers = relayedServices.map((service) =>
    options.supervisor.onChildMessage(service, (message) => {
      if (!('requestId' in message) || !message.requestId) return;
      if (!isControlResponse(message)) return;

      const pending = pendingByRequestId.get(message.requestId);
      if (!pending) return;
      clearTimeout(pending.timeout);
      pendingByRequestId.delete(message.requestId);
      writeFrame(pending.socket, message);
    })
  );

  function handleFrame(socket: net.Socket, frame: string): void {
    if (!frame) return;

    let parsed: unknown;
    try {
      parsed = JSON.parse(frame);
    } catch {
      writeFrame(socket, {
        version: SERVICE_PROTOCOL_VERSION,
        type: 'service.error',
        code: 'INVALID_MESSAGE',
        message: 'Invalid control frame'
      });
      return;
    }

    const message = parseIpcMessage(parsed);
    if (!message) {
      writeFrame(socket, {
        version: SERVICE_PROTOCOL_VERSION,
        type: 'service.error',
        code: 'INVALID_MESSAGE',
        message: 'Invalid control frame'
      });
      return;
    }

    if (!isControlRequest(message)) {
      if ('requestId' in message) {
        writeFrame(socket, {
          version: SERVICE_PROTOCOL_VERSION,
          type: 'service.error',
          requestId: message.requestId,
          code: 'UNSUPPORTED_MESSAGE',
          message: 'Only issuer fault/config and relying party fault controls are relayed'
        });
      }
      return;
    }

    const target = CONTROL_REQUEST_TARGETS[message.type];
    const forwarded = options.supervisor.sendToChild(target, message);
    if (!forwarded) {
      writeFrame(socket, {
        version: SERVICE_PROTOCOL_VERSION,
        type: 'service.error',
        requestId: message.requestId,
        service: target,
        code: 'SERVICE_UNAVAILABLE',
        message: `${target} is not managed by this supervisor`
      });
      return;
    }

    const requestId = message.requestId;
    const timeout = setTimeout(() => {
      pendingByRequestId.delete(requestId);
      writeFrame(socket, {
        version: SERVICE_PROTOCOL_VERSION,
        type: 'service.error',
        requestId,
        service: target,
        code: 'FAULT_CONTROL_TIMEOUT',
        message: `Timed out waiting for ${target} response`
      });
    }, CHILD_RESPONSE_TIMEOUT_MS);

    pendingByRequestId.set(requestId, { socket, timeout });
  }

  const server = net.createServer((socket) => {
    let buffer = '';

    socket.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      if (buffer.length > MAX_FRAME_BYTES) {
        writeFrame(socket, {
          version: SERVICE_PROTOCOL_VERSION,
          type: 'service.error',
          code: 'FRAME_TOO_LARGE',
          message: 'Control frame exceeded the maximum size'
        });
        socket.destroy();
        return;
      }

      let newlineIndex = buffer.indexOf(FRAME_DELIMITER);
      while (newlineIndex !== -1) {
        const frame = buffer.slice(0, newlineIndex);
        buffer = buffer.slice(newlineIndex + 1);
        newlineIndex = buffer.indexOf(FRAME_DELIMITER);
        handleFrame(socket, frame);
      }
    });

    socket.on('close', () => {
      for (const [requestId, pending] of pendingByRequestId) {
        if (pending.socket !== socket) continue;
        clearTimeout(pending.timeout);
        pendingByRequestId.delete(requestId);
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(endpoint, () => resolve());
  });

  if (process.platform !== 'win32') {
    await chmod(endpoint, 0o600);
  }

  return {
    endpoint,
    close: async () => {
      for (const unsubscribe of unsubscribers) unsubscribe();
      for (const pending of pendingByRequestId.values()) clearTimeout(pending.timeout);
      pendingByRequestId.clear();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (process.platform !== 'win32') {
        await rm(path.dirname(endpoint), { recursive: true, force: true });
      }
    }
  };
}
