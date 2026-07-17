export const SERVICE_PROTOCOL_VERSION = 1 as const;

export const localServiceNames = ['credential-issuer', 'relying-party', 'trust-anchor'] as const;
export type LocalServiceName = (typeof localServiceNames)[number];

export type ServiceReadyMessage = {
  version: typeof SERVICE_PROTOCOL_VERSION;
  type: 'service.ready';
  service: LocalServiceName;
  endpoint: string;
};

export type ServiceHealthMessage = {
  version: typeof SERVICE_PROTOCOL_VERSION;
  type: 'service.health';
  requestId: string;
};

export type ServiceHealthResponse = {
  version: typeof SERVICE_PROTOCOL_VERSION;
  type: 'service.health';
  requestId: string;
  service: LocalServiceName;
  status: 'ok';
};

export type ServiceStopMessage = {
  version: typeof SERVICE_PROTOCOL_VERSION;
  type: 'service.stop';
  requestId: string;
};

export type ServiceStoppedMessage = {
  version: typeof SERVICE_PROTOCOL_VERSION;
  type: 'service.stopped';
  requestId: string;
  service: LocalServiceName;
};

/** Reserved transport hook for future IssuerFaultProfile controls. */
export type IssuerFaultMessage = {
  version: typeof SERVICE_PROTOCOL_VERSION;
  type: `issuer.fault.${string}`;
  requestId: string;
};

export type ServiceErrorMessage = {
  version: typeof SERVICE_PROTOCOL_VERSION;
  type: 'service.error';
  requestId?: string;
  service?: LocalServiceName;
  code: string;
  message: string;
};

export type IpcMessage =
  | IssuerFaultMessage
  | ServiceErrorMessage
  | ServiceHealthMessage
  | ServiceHealthResponse
  | ServiceReadyMessage
  | ServiceStopMessage
  | ServiceStoppedMessage;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isServiceName(value: unknown): value is LocalServiceName {
  return typeof value === 'string' && localServiceNames.includes(value as LocalServiceName);
}

function hasProtocolHeader(value: Record<string, unknown>): boolean {
  return value.version === SERVICE_PROTOCOL_VERSION && typeof value.type === 'string';
}

/** Validates untrusted Node IPC payloads without logging their contents. */
export function parseIpcMessage(value: unknown): IpcMessage | undefined {
  if (!isRecord(value) || !hasProtocolHeader(value)) return undefined;

  const requestId = value.requestId;
  if (value.type === 'service.ready' && isServiceName(value.service) && typeof value.endpoint === 'string') {
    return value as ServiceReadyMessage;
  }
  if (value.type === 'service.health' && typeof requestId === 'string') {
    return isServiceName(value.service) && value.status === 'ok'
      ? (value as ServiceHealthResponse)
      : (value as ServiceHealthMessage);
  }
  if (value.type === 'service.stop' && typeof requestId === 'string') return value as ServiceStopMessage;
  if (value.type === 'service.stopped' && typeof requestId === 'string' && isServiceName(value.service)) {
    return value as ServiceStoppedMessage;
  }
  if (value.type === 'service.error' && typeof value.code === 'string' && typeof value.message === 'string') {
    return value as ServiceErrorMessage;
  }
  const type = value.type;
  if (typeof type === 'string' && type.startsWith('issuer.fault.') && typeof requestId === 'string') {
    return value as IssuerFaultMessage;
  }
  return undefined;
}

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
