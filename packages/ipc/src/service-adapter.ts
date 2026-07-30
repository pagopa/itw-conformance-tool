import { parseIpcMessage } from './messages.js';
import { SERVICE_PROTOCOL_VERSION } from './protocol.js';

import type { IpcMessage, LocalServiceName } from './messages.js';
import type { IssuerConfig } from './messages.js';
import type { IssuerFaultProfile, RpFaultProfile, TrustAnchorFaultProfile } from '@itw-conformance-tool/faults';

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

export interface TrustAnchorFaultActivationRequest {
  scenarioId: string;
  specVersion: string;
  profile: TrustAnchorFaultProfile;
}

export interface TrustAnchorFaultDeactivationRequest {
  scenarioId: string;
}

export interface TrustAnchorFaultActivationResult {
  ok: boolean;
  code?: string;
  message?: string;
}

export interface TrustAnchorFaultHandlers {
  activate: (request: TrustAnchorFaultActivationRequest) => Promise<TrustAnchorFaultActivationResult>;
  deactivate: (request: TrustAnchorFaultDeactivationRequest) => Promise<TrustAnchorFaultActivationResult>;
}

export interface IssuerConfigActivationRequest {
  scenarioId: string;
  config: IssuerConfig;
}

export interface IssuerConfigDeactivationRequest {
  scenarioId: string;
}

export interface IssuerConfigActivationResult {
  ok: boolean;
  code?: string;
  message?: string;
}

export interface IssuerConfigHandlers {
  activate: (request: IssuerConfigActivationRequest) => Promise<IssuerConfigActivationResult>;
  deactivate: (request: IssuerConfigDeactivationRequest) => Promise<IssuerConfigActivationResult>;
}

export interface RpFaultActivationRequest {
  scenarioId: string;
  specVersion: string;
  profile: RpFaultProfile;
}

export interface RpFaultDeactivationRequest {
  scenarioId: string;
}

export interface RpFaultActivationResult {
  ok: boolean;
  code?: string;
  message?: string;
}

export interface RpFaultHandlers {
  activate: (request: RpFaultActivationRequest) => Promise<RpFaultActivationResult>;
  deactivate: (request: RpFaultDeactivationRequest) => Promise<RpFaultActivationResult>;
}

/** Acknowledgement sent back for a successfully handled control request. */
type ControlAcknowledgementType =
  | 'issuer.config.activated'
  | 'issuer.config.deactivated'
  | 'issuer.fault.activated'
  | 'issuer.fault.deactivated'
  | 'rp.fault.activated'
  | 'rp.fault.deactivated';

export interface ServiceIpcAdapterOptions {
  endpoint: string;
  service: LocalServiceName;
  stop: () => Promise<void>;
  issuerConfig?: IssuerConfigHandlers;
  issuerFaults?: IssuerFaultHandlers;
  rpFaults?: RpFaultHandlers;
  trustAnchorFaults?: TrustAnchorFaultHandlers;
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

    /**
     * Runs one control request (fault/config, activate/deactivate) and answers
     * with its acknowledgement message, or with `service.error` when the
     * control surface is not configured, the handler rejects the request, or
     * the handler itself throws.
     */
    const handleControlRequest = <TResult extends { ok: boolean; code?: string; message?: string }>(input: {
      requestId: string;
      scenarioId: string;
      handler: (() => Promise<TResult>) | undefined;
      acknowledgement: ControlAcknowledgementType;
      unsupportedMessage: string;
      failureCode: string;
      failureMessage: string;
    }): void => {
      const fail = (code: string, failureMessage: string): void =>
        send({
          version: SERVICE_PROTOCOL_VERSION,
          type: 'service.error',
          requestId: input.requestId,
          service: options.service,
          code,
          message: failureMessage
        });

      if (!input.handler) {
        fail('UNSUPPORTED_MESSAGE', input.unsupportedMessage);
        return;
      }

      void input.handler().then(
        (result) => {
          if (!result.ok) {
            fail(result.code ?? input.failureCode, result.message ?? input.failureMessage);
            return;
          }

          // Every acknowledgement variant carries exactly these members, but a
          // union-typed discriminant is not narrowed back to one variant.
          send({
            version: SERVICE_PROTOCOL_VERSION,
            type: input.acknowledgement,
            requestId: input.requestId,
            scenarioId: input.scenarioId
          } as IpcMessage);
        },
        () => fail(input.failureCode, input.failureMessage)
      );
    };

    if (message.type === 'issuer.fault.activate') {
      const faults = options.issuerFaults;
      handleControlRequest({
        requestId: message.requestId,
        scenarioId: message.scenarioId,
        handler:
          faults &&
          (() =>
            faults.activate({
              scenarioId: message.scenarioId,
              specVersion: message.specVersion,
              profile: message.profile
            })),
        acknowledgement: 'issuer.fault.activated',
        unsupportedMessage: 'Issuer fault controls are not configured',
        failureCode: 'FAULT_ACTIVATION_FAILED',
        failureMessage: 'Issuer fault activation failed'
      });
      return;
    }

    if (message.type === 'issuer.fault.deactivate') {
      const faults = options.issuerFaults;
      handleControlRequest({
        requestId: message.requestId,
        scenarioId: message.scenarioId,
        handler: faults && (() => faults.deactivate({ scenarioId: message.scenarioId })),
        acknowledgement: 'issuer.fault.deactivated',
        unsupportedMessage: 'Issuer fault controls are not configured',
        failureCode: 'FAULT_DEACTIVATION_FAILED',
        failureMessage: 'Issuer fault deactivation failed'
      });
      return;
    }

    if (message.type === 'trust-anchor.fault.activate') {
      if (!options.trustAnchorFaults) {
        send({
          version: SERVICE_PROTOCOL_VERSION,
          type: 'service.error',
          requestId: message.requestId,
          service: options.service,
          code: 'UNSUPPORTED_MESSAGE',
          message: 'Trust Anchor fault controls are not configured'
        });
        return;
      }

      void options.trustAnchorFaults
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
                message: result.message ?? 'Trust Anchor fault activation failed'
              });
              return;
            }

            send({
              version: SERVICE_PROTOCOL_VERSION,
              type: 'trust-anchor.fault.activated',
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
              message: 'Trust Anchor fault activation failed'
            })
        );
      return;
    }

    if (message.type === 'trust-anchor.fault.deactivate') {
      if (!options.trustAnchorFaults) {
        send({
          version: SERVICE_PROTOCOL_VERSION,
          type: 'service.error',
          requestId: message.requestId,
          service: options.service,
          code: 'UNSUPPORTED_MESSAGE',
          message: 'Trust Anchor fault controls are not configured'
        });
        return;
      }

      void options.trustAnchorFaults.deactivate({ scenarioId: message.scenarioId }).then(
        (result) => {
          if (!result.ok) {
            send({
              version: SERVICE_PROTOCOL_VERSION,
              type: 'service.error',
              requestId: message.requestId,
              service: options.service,
              code: result.code ?? 'FAULT_DEACTIVATION_FAILED',
              message: result.message ?? 'Trust Anchor fault deactivation failed'
            });
            return;
          }

          send({
            version: SERVICE_PROTOCOL_VERSION,
            type: 'trust-anchor.fault.deactivated',
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
            message: 'Trust Anchor fault deactivation failed'
          })
      );
      return;
    }

    if (message.type === 'issuer.config.activate') {
      const config = options.issuerConfig;
      handleControlRequest({
        requestId: message.requestId,
        scenarioId: message.scenarioId,
        handler: config && (() => config.activate({ scenarioId: message.scenarioId, config: message.config })),
        acknowledgement: 'issuer.config.activated',
        unsupportedMessage: 'Issuer config controls are not configured',
        failureCode: 'CONFIG_ACTIVATION_FAILED',
        failureMessage: 'Issuer config activation failed'
      });
      return;
    }

    if (message.type === 'issuer.config.deactivate') {
      const config = options.issuerConfig;
      handleControlRequest({
        requestId: message.requestId,
        scenarioId: message.scenarioId,
        handler: config && (() => config.deactivate({ scenarioId: message.scenarioId })),
        acknowledgement: 'issuer.config.deactivated',
        unsupportedMessage: 'Issuer config controls are not configured',
        failureCode: 'CONFIG_DEACTIVATION_FAILED',
        failureMessage: 'Issuer config deactivation failed'
      });
      return;
    }

    if (message.type === 'rp.fault.activate') {
      const faults = options.rpFaults;
      handleControlRequest({
        requestId: message.requestId,
        scenarioId: message.scenarioId,
        handler:
          faults &&
          (() =>
            faults.activate({
              scenarioId: message.scenarioId,
              specVersion: message.specVersion,
              profile: message.profile
            })),
        acknowledgement: 'rp.fault.activated',
        unsupportedMessage: 'Relying party fault controls are not configured',
        failureCode: 'FAULT_ACTIVATION_FAILED',
        failureMessage: 'Relying party fault activation failed'
      });
      return;
    }

    if (message.type === 'rp.fault.deactivate') {
      const faults = options.rpFaults;
      handleControlRequest({
        requestId: message.requestId,
        scenarioId: message.scenarioId,
        handler: faults && (() => faults.deactivate({ scenarioId: message.scenarioId })),
        acknowledgement: 'rp.fault.deactivated',
        unsupportedMessage: 'Relying party fault controls are not configured',
        failureCode: 'FAULT_DEACTIVATION_FAILED',
        failureMessage: 'Relying party fault deactivation failed'
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
