export { attachServiceIpcAdapter } from './service-adapter.js';
export { localServiceNames, SERVICE_PROTOCOL_VERSION } from './protocol.js';
export { parseIpcMessage } from './messages.js';

export type {
  IpcMessage,
  IssuerFaultMessage,
  LocalServiceName,
  ServiceErrorMessage,
  ServiceHealthMessage,
  ServiceHealthResponse,
  ServiceReadyMessage,
  ServiceStoppedMessage,
  ServiceStopMessage
} from './messages.js';
export type { ServiceIpcAdapterOptions } from './service-adapter.js';
