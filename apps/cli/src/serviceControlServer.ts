import { randomUUID } from 'node:crypto';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { parseIpcMessage, SERVICE_PROTOCOL_VERSION } from '@itw-conformance-tool/ipc';

import type { ServiceSupervisor } from './supervisor.js';
import type { IpcMessage, LocalServiceName } from '@itw-conformance-tool/ipc';

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
  expectedService: LocalServiceName;
  socket: net.Socket;
  timeout: NodeJS.Timeout;
}

interface EndpointAllocation {
  cleanup: () => Promise<void>;
  listenOptions: string | net.ListenOptions;
  resolveEndpoint: (server: net.Server) => string;
  shouldChmodSocket: boolean;
}

function writeFrame(socket: net.Socket, message: IpcMessage): void {
  if (socket.writable) socket.write(`${JSON.stringify(message)}${FRAME_DELIMITER}`);
}

async function allocateEndpoint(): Promise<EndpointAllocation> {
  if (process.env.ITWCT_CONTROL_TCP === '1') {
    return {
      cleanup: async () => undefined,
      listenOptions: { host: '127.0.0.1', port: 0 },
      resolveEndpoint: (server) => {
        const address = server.address();
        if (!address || typeof address === 'string') throw new Error('Unable to resolve TCP control endpoint');
        return `tcp://${address.address}:${address.port}`;
      },
      shouldChmodSocket: false
    };
  }

  if (process.platform === 'win32') {
    const endpoint = `\\\\.\\pipe\\itwct-control-${randomUUID()}`;
    return {
      cleanup: async () => undefined,
      listenOptions: endpoint,
      resolveEndpoint: () => endpoint,
      shouldChmodSocket: false
    };
  }

  const dir = await mkdtemp(path.join(process.env.ITWCT_CONTROL_TMPDIR ?? tmpdir(), 'itwct-control-'));
  await chmod(dir, 0o700);
  const endpoint = path.join(dir, 'control.sock');
  return {
    cleanup: () => rm(dir, { recursive: true, force: true }),
    listenOptions: endpoint,
    resolveEndpoint: () => endpoint,
    shouldChmodSocket: true
  };
}

/**
 * Local-only control relay between the Vitest conformance runner process and
 * the CLI-owned service children. Only allow-listed local control messages
 * are relayed, and only to their owning managed child. This is
 * never exposed as an HTTP route, uses a
 * random endpoint in a private temporary directory, owner-only permissions
 * where supported, newline-delimited framing, bounded frame sizes, and
 * request-ID correlation.
 */
export async function startServiceControlServer(options: ServiceControlServerOptions): Promise<ServiceControlServer> {
  const endpointAllocation = await allocateEndpoint();
  const pendingByRequestId = new Map<string, PendingChildResponse>();

  const responseTypes = new Set<IpcMessage['type']>([
    'issuer.fault.activated',
    'issuer.fault.deactivated',
    'issuer.config.activated',
    'issuer.config.deactivated',
    'trust-anchor.fault.activated',
    'trust-anchor.fault.deactivated',
    'service.error'
  ]);

  const subscriptions: Array<() => void> = [];

  function subscribeToChild(service: LocalServiceName): void {
    subscriptions.push(
      options.supervisor.onChildMessage(service, (message) => {
        if (!('requestId' in message) || !message.requestId) return;
        if (!responseTypes.has(message.type)) return;

        const pending = pendingByRequestId.get(message.requestId);
        if (!pending || pending.expectedService !== service) return;

        clearTimeout(pending.timeout);
        pendingByRequestId.delete(message.requestId);
        writeFrame(pending.socket, message);
      })
    );
  }

  subscribeToChild('credential-issuer');
  subscribeToChild('trust-anchor');

  function routeServiceFor(message: IpcMessage): LocalServiceName | undefined {
    if (!('requestId' in message) || !message.requestId) return;

    if (
      message.type === 'issuer.fault.activate' ||
      message.type === 'issuer.fault.deactivate' ||
      message.type === 'issuer.config.activate' ||
      message.type === 'issuer.config.deactivate'
    ) {
      return 'credential-issuer';
    }

    if (message.type === 'trust-anchor.fault.activate' || message.type === 'trust-anchor.fault.deactivate') {
      return 'trust-anchor';
    }

    return undefined;
  }

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

    const targetService = routeServiceFor(message);
    if (!targetService) {
      if ('requestId' in message) {
        writeFrame(socket, {
          version: SERVICE_PROTOCOL_VERSION,
          type: 'service.error',
          requestId: message.requestId,
          code: 'UNSUPPORTED_MESSAGE',
          message: 'Only issuer, issuer config, and Trust Anchor fault controls are relayed'
        });
      }
      return;
    }
    if (!('requestId' in message)) return;
    const requestId = message.requestId;
    if (typeof requestId !== 'string') return;

    const forwarded = options.supervisor.sendToChild(targetService, message);
    if (!forwarded) {
      writeFrame(socket, {
        version: SERVICE_PROTOCOL_VERSION,
        type: 'service.error',
        requestId,
        code: 'SERVICE_UNAVAILABLE',
        message: `${targetService} is not managed by this supervisor`
      });
      return;
    }

    const timeout = setTimeout(() => {
      pendingByRequestId.delete(requestId);
      writeFrame(socket, {
        version: SERVICE_PROTOCOL_VERSION,
        type: 'service.error',
        requestId,
        code: 'FAULT_CONTROL_TIMEOUT',
        message: `Timed out waiting for ${targetService} response`
      });
    }, CHILD_RESPONSE_TIMEOUT_MS);

    pendingByRequestId.set(requestId, { expectedService: targetService, socket, timeout });
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
    server.listen(endpointAllocation.listenOptions, () => resolve());
  });

  const endpoint = endpointAllocation.resolveEndpoint(server);

  if (endpointAllocation.shouldChmodSocket) {
    await chmod(endpoint, 0o600);
  }

  return {
    endpoint,
    close: async () => {
      for (const unsubscribe of subscriptions) unsubscribe();
      for (const pending of pendingByRequestId.values()) clearTimeout(pending.timeout);
      pendingByRequestId.clear();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await endpointAllocation.cleanup();
    }
  };
}
