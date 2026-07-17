import { z } from 'zod';

import { localServiceNames, SERVICE_PROTOCOL_VERSION } from './protocol.js';

const protocolHeaderSchema = z.object({
  version: z.literal(SERVICE_PROTOCOL_VERSION)
});

const serviceNameSchema = z.enum(localServiceNames);
const requestIdSchema = z.string();

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

const issuerFaultMessageSchema = protocolHeaderSchema
  .extend({
    type: z.custom<`issuer.fault.${string}`>((value) => typeof value === 'string' && value.startsWith('issuer.fault.')),
    requestId: requestIdSchema
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
  issuerFaultMessageSchema,
  serviceErrorMessageSchema
]);

export type LocalServiceName = z.infer<typeof serviceNameSchema>;
export type ServiceReadyMessage = z.infer<typeof serviceReadyMessageSchema>;
export type ServiceHealthMessage = z.infer<typeof serviceHealthMessageSchema>;
export type ServiceHealthResponse = z.infer<typeof serviceHealthResponseSchema>;
export type ServiceStopMessage = z.infer<typeof serviceStopMessageSchema>;
export type ServiceStoppedMessage = z.infer<typeof serviceStoppedMessageSchema>;
/** Reserved transport hook for future IssuerFaultProfile controls. */
export type IssuerFaultMessage = z.infer<typeof issuerFaultMessageSchema>;
export type ServiceErrorMessage = z.infer<typeof serviceErrorMessageSchema>;
export type IpcMessage = z.infer<typeof ipcMessageSchema>;

/** Validates untrusted Node IPC payloads without logging their contents. */
export function parseIpcMessage(value: unknown): IpcMessage | undefined {
  const result = ipcMessageSchema.safeParse(value);
  return result.success ? result.data : undefined;
}
