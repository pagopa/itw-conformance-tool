export { attachServiceIpcAdapter } from './service-adapter.js';
export { createServiceControlClient } from './service-control-client.js';
export { localServiceNames, SERVICE_PROTOCOL_VERSION } from './protocol.js';
export { parseIpcMessage } from './messages.js';

export type {
  IpcMessage,
  IssuerFaultActivateMessage,
  IssuerFaultActivatedMessage,
  IssuerFaultDeactivateMessage,
  IssuerFaultDeactivatedMessage,
  LocalServiceName,
  ServiceErrorMessage,
  ServiceHealthMessage,
  ServiceHealthResponse,
  ServiceReadyMessage,
  ServiceStoppedMessage,
  ServiceStopMessage
} from './messages.js';
export type {
  IssuerFaultActivationRequest,
  IssuerFaultActivationResult,
  IssuerFaultDeactivationRequest,
  IssuerFaultHandlers,
  ServiceIpcAdapterOptions
} from './service-adapter.js';
export type { ServiceControlClient, ServiceControlClientOptions } from './service-control-client.js';
