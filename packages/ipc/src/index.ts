export { attachServiceIpcAdapter } from './service-adapter.js';
export { createServiceControlClient } from './service-control-client.js';
export { localServiceNames, SERVICE_PROTOCOL_VERSION } from './protocol.js';
export { parseIpcMessage } from './messages.js';

export type {
  IpcMessage,
  IssuerConfig,
  IssuerConfigActivateMessage,
  IssuerConfigActivatedMessage,
  IssuerConfigDeactivateMessage,
  IssuerConfigDeactivatedMessage,
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
  ServiceStopMessage,
  TrustAnchorFaultActivateMessage,
  TrustAnchorFaultActivatedMessage,
  TrustAnchorFaultDeactivateMessage,
  TrustAnchorFaultDeactivatedMessage
} from './messages.js';
export type {
  IssuerConfigActivationRequest,
  IssuerConfigActivationResult,
  IssuerConfigDeactivationRequest,
  IssuerConfigHandlers,
  IssuerFaultActivationRequest,
  IssuerFaultActivationResult,
  IssuerFaultDeactivationRequest,
  IssuerFaultHandlers,
  ServiceIpcAdapterOptions,
  TrustAnchorFaultActivationRequest,
  TrustAnchorFaultActivationResult,
  TrustAnchorFaultDeactivationRequest,
  TrustAnchorFaultHandlers
} from './service-adapter.js';
export type { ServiceControlClient, ServiceControlClientOptions } from './service-control-client.js';
