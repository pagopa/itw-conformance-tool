import { parseIpcMessage } from './messages.js';
import { SERVICE_PROTOCOL_VERSION } from './protocol.js';

import type { IpcMessage, LocalServiceName } from './messages.js';
import type { IssuerFaultProfile } from '@itw-conformance-tool/faults';

export interface IssuerFaultActivationRequest {
  scenarioId: string;
  specVersion: string;
  profile: IssuerFaultProfile;
}

export interface IssuerFaultDeactivationRequest {
  scenarioId: string;
}

export interface IssuerFaultActivationResult {
  ok: boolean;
  code?: string;
  message?: string;
}

export interface IssuerFaultHandlers {
  activate: (request: IssuerFaultActivationRequest) => Promise<IssuerFaultActivationResult>;
  deactivate: (request: IssuerFaultDeactivationRequest) => Promise<IssuerFaultActivationResult>;
}

export interface ServiceIpcAdapterOptions {
  endpoint: string;
  service: LocalServiceName;
  stop: () => Promise<void>;
  issuerFaults?: IssuerFaultHandlers;
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

    if (message.type === 'issuer.fault.activate') {
      if (!options.issuerFaults) {
        send({
          version: SERVICE_PROTOCOL_VERSION,
          type: 'service.error',
          requestId: message.requestId,
          service: options.service,
          code: 'UNSUPPORTED_MESSAGE',
          message: 'Issuer fault controls are not configured'
        });
        return;
      }

      void options.issuerFaults
        .activate({ scenarioId: message.scenarioId, specVersion: message.specVersion, profile: message.profile })
        .then(
          (result) => {
            if (!result.ok) {
              send({
                version: SERVICE_PROTOCOL_VERSION,
                type: 'service.error',
                requestId: message.requestId,
                service: options.service,
                code: result.code ?? 'FAULT_ACTIVATION_FAILED',
                message: result.message ?? 'Issuer fault activation failed'
              });
              return;
            }

            send({
              version: SERVICE_PROTOCOL_VERSION,
              type: 'issuer.fault.activated',
              requestId: message.requestId,
              scenarioId: message.scenarioId
            });
          },
          () =>
            send({
              version: SERVICE_PROTOCOL_VERSION,
              type: 'service.error',
              requestId: message.requestId,
              service: options.service,
              code: 'FAULT_ACTIVATION_FAILED',
              message: 'Issuer fault activation failed'
            })
        );
      return;
    }

    if (message.type === 'issuer.fault.deactivate') {
      if (!options.issuerFaults) {
        send({
          version: SERVICE_PROTOCOL_VERSION,
          type: 'service.error',
          requestId: message.requestId,
          service: options.service,
          code: 'UNSUPPORTED_MESSAGE',
          message: 'Issuer fault controls are not configured'
        });
        return;
      }

      void options.issuerFaults.deactivate({ scenarioId: message.scenarioId }).then(
        (result) => {
          if (!result.ok) {
            send({
              version: SERVICE_PROTOCOL_VERSION,
              type: 'service.error',
              requestId: message.requestId,
              service: options.service,
              code: result.code ?? 'FAULT_DEACTIVATION_FAILED',
              message: result.message ?? 'Issuer fault deactivation failed'
            });
            return;
          }

          send({
            version: SERVICE_PROTOCOL_VERSION,
            type: 'issuer.fault.deactivated',
            requestId: message.requestId,
            scenarioId: message.scenarioId
          });
        },
        () =>
          send({
            version: SERVICE_PROTOCOL_VERSION,
            type: 'service.error',
            requestId: message.requestId,
            service: options.service,
            code: 'FAULT_DEACTIVATION_FAILED',
            message: 'Issuer fault deactivation failed'
          })
      );
    }
  });

  send({
    version: SERVICE_PROTOCOL_VERSION,
    type: 'service.ready',
    service: options.service,
    endpoint: options.endpoint
  });
}
