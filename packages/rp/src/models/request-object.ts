import { z } from 'zod';

export const requestObjectSchema = z.object({
  iss: z.string().url(),
  aud: z.string(),
  client_id: z.string(),
  nonce: z.string(),
  state: z.string(),
  iat: z.number().int(),
  exp: z.number().int(),
  presentation_definition: z.record(z.unknown()).optional()
});

export type RequestObject = z.infer<typeof requestObjectSchema>;

export function validateRequestObject(obj: unknown): RequestObject {
  return requestObjectSchema.parse(obj);
}

export function isRequestObjectExpired(requestObject: RequestObject): boolean {
  return Math.floor(Date.now() / 1000) > requestObject.exp;
}
