import { issuerFaultProfileSchema } from '@itw-conformance-tool/faults';
import { z } from 'zod';

import { localServiceNames, SERVICE_PROTOCOL_VERSION } from './protocol.js';

const protocolHeaderSchema = z.object({
  version: z.literal(SERVICE_PROTOCOL_VERSION)
});

const serviceNameSchema = z.enum(localServiceNames);
const requestIdSchema = z.string();

const issuerConfigSchema = z
  .object({
    batchIssuanceByDeferred: z.boolean(),
    accessTokenTtlSeconds: z.number().int().positive().optional(),
    refreshTokenTtlSeconds: z.number().int().positive().optional(),
    statusList: z
      .object({
        bits: z.literal(4),
        ttlSeconds: z.number().int().positive().optional(),
        values: z.array(z.number().int().min(0).max(15)).nonempty()
      })
      .strict()
      .optional()
  })
  .strict();

const serviceReadyMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('service.ready'),
    service: serviceNameSchema,
    endpoint: z.string()
  })
  .strict();

const serviceHealthMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('service.health'),
    requestId: requestIdSchema
  })
  .strict();

const serviceHealthResponseSchema = protocolHeaderSchema
  .extend({
    type: z.literal('service.health'),
    requestId: requestIdSchema,
    service: serviceNameSchema,
    status: z.literal('ok')
  })
  .strict();

const serviceStopMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('service.stop'),
    requestId: requestIdSchema
  })
  .strict();

const serviceStoppedMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('service.stopped'),
    requestId: requestIdSchema,
    service: serviceNameSchema
  })
  .strict();

const issuerFaultActivateMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('issuer.fault.activate'),
    requestId: requestIdSchema,
    scenarioId: z.string(),
    specVersion: z.string(),
    profile: issuerFaultProfileSchema
  })
  .strict();

const issuerFaultActivatedMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('issuer.fault.activated'),
    requestId: requestIdSchema,
    scenarioId: z.string()
  })
  .strict();

const issuerFaultDeactivateMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('issuer.fault.deactivate'),
    requestId: requestIdSchema,
    scenarioId: z.string()
  })
  .strict();

const issuerFaultDeactivatedMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('issuer.fault.deactivated'),
    requestId: requestIdSchema,
    scenarioId: z.string()
  })
  .strict();

const issuerConfigActivateMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('issuer.config.activate'),
    requestId: requestIdSchema,
    scenarioId: z.string(),
    config: issuerConfigSchema
  })
  .strict();

const issuerConfigActivatedMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('issuer.config.activated'),
    requestId: requestIdSchema,
    scenarioId: z.string()
  })
  .strict();

const issuerConfigDeactivateMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('issuer.config.deactivate'),
    requestId: requestIdSchema,
    scenarioId: z.string()
  })
  .strict();

const issuerConfigDeactivatedMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('issuer.config.deactivated'),
    requestId: requestIdSchema,
    scenarioId: z.string()
  })
  .strict();

const serviceErrorMessageSchema = protocolHeaderSchema
  .extend({
    type: z.literal('service.error'),
    requestId: requestIdSchema.optional(),
    service: serviceNameSchema.optional(),
    code: z.string(),
    message: z.string()
  })
  .strict();

const ipcMessageSchema = z.union([
  serviceReadyMessageSchema,
  serviceHealthResponseSchema,
  serviceHealthMessageSchema,
  serviceStopMessageSchema,
  serviceStoppedMessageSchema,
  issuerFaultActivateMessageSchema,
  issuerFaultActivatedMessageSchema,
  issuerFaultDeactivateMessageSchema,
  issuerFaultDeactivatedMessageSchema,
  issuerConfigActivateMessageSchema,
  issuerConfigActivatedMessageSchema,
  issuerConfigDeactivateMessageSchema,
  issuerConfigDeactivatedMessageSchema,
  serviceErrorMessageSchema
]);

export type LocalServiceName = z.infer<typeof serviceNameSchema>;
export type ServiceReadyMessage = z.infer<typeof serviceReadyMessageSchema>;
export type ServiceHealthMessage = z.infer<typeof serviceHealthMessageSchema>;
export type ServiceHealthResponse = z.infer<typeof serviceHealthResponseSchema>;
export type ServiceStopMessage = z.infer<typeof serviceStopMessageSchema>;
export type ServiceStoppedMessage = z.infer<typeof serviceStoppedMessageSchema>;
export type IssuerFaultActivateMessage = z.infer<typeof issuerFaultActivateMessageSchema>;
export type IssuerFaultActivatedMessage = z.infer<typeof issuerFaultActivatedMessageSchema>;
export type IssuerFaultDeactivateMessage = z.infer<typeof issuerFaultDeactivateMessageSchema>;
export type IssuerFaultDeactivatedMessage = z.infer<typeof issuerFaultDeactivatedMessageSchema>;
export type IssuerConfig = z.infer<typeof issuerConfigSchema>;
export type IssuerConfigActivateMessage = z.infer<typeof issuerConfigActivateMessageSchema>;
export type IssuerConfigActivatedMessage = z.infer<typeof issuerConfigActivatedMessageSchema>;
export type IssuerConfigDeactivateMessage = z.infer<typeof issuerConfigDeactivateMessageSchema>;
export type IssuerConfigDeactivatedMessage = z.infer<typeof issuerConfigDeactivatedMessageSchema>;
export type ServiceErrorMessage = z.infer<typeof serviceErrorMessageSchema>;
export type IpcMessage = z.infer<typeof ipcMessageSchema>;

/** Validates untrusted Node IPC payloads without logging their contents. */
export function parseIpcMessage(value: unknown): IpcMessage | undefined {
  const result = ipcMessageSchema.safeParse(value);
  return result.success ? result.data : undefined;
}
