import { parseIpcMessage } from './messages.js';
import { SERVICE_PROTOCOL_VERSION } from './protocol.js';

import type { IpcMessage, LocalServiceName } from './messages.js';

export interface ServiceIpcAdapterOptions {
  endpoint: string;
  service: LocalServiceName;
  stop: () => Promise<void>;
}

/**
 * Attaches the service-side half of the IPC protocol. It is a no-op for normal,
 * standalone processes, so local development remains unchanged.
 */
export function attachServiceIpcAdapter(options: ServiceIpcAdapterOptions): void {
  if (typeof process.send !== 'function' || !process.connected) return;

  const send = (message: IpcMessage): void => {
    if (process.connected) process.send?.(message);
  };

  process.on('message', (rawMessage: unknown) => {
    const message = parseIpcMessage(rawMessage);
    if (!message) {
      send({
        version: SERVICE_PROTOCOL_VERSION,
        type: 'service.error',
        service: options.service,
        code: 'INVALID_MESSAGE',
        message: 'Invalid IPC message'
      });
      return;
    }

    if (message.type === 'service.health' && !('status' in message)) {
      send({
        version: SERVICE_PROTOCOL_VERSION,
        type: 'service.health',
        requestId: message.requestId,
        service: options.service,
        status: 'ok'
      });
      return;
    }

    if (message.type === 'service.stop') {
      void options.stop().then(
        () => {
          send({
            version: SERVICE_PROTOCOL_VERSION,
            type: 'service.stopped',
            requestId: message.requestId,
            service: options.service
          });
          process.disconnect();
        },
        () =>
          send({
            version: SERVICE_PROTOCOL_VERSION,
            type: 'service.error',
            requestId: message.requestId,
            service: options.service,
            code: 'STOP_FAILED',
            message: 'Service shutdown failed'
          })
      );
      return;
    }

    if (message.type.startsWith('issuer.fault.') && 'requestId' in message) {
      send({
        version: SERVICE_PROTOCOL_VERSION,
        type: 'service.error',
        requestId: message.requestId,
        service: options.service,
        code: 'UNSUPPORTED_MESSAGE',
        message: 'Issuer fault controls are not configured'
      });
    }
  });

  send({
    version: SERVICE_PROTOCOL_VERSION,
    type: 'service.ready',
    service: options.service,
    endpoint: options.endpoint
  });
}
