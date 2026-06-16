import { z } from 'zod';

export const jwkSchema = z.looseObject({
  kty: z.string(),
  kid: z.string().min(1),
  use: z.enum(['sig', 'enc']).optional(),
  alg: z.string().optional(),
  key_ops: z.array(z.string()).optional(),

  // RSA fields
  n: z.string().optional(),
  e: z.string().optional(),

  // EC / OKP private key scalar
  d: z.string().optional(),

  // EC / OKP public key coordinates
  x: z.string().optional(),
  y: z.string().optional(),
  crv: z.string().optional()
});

export const jwksSchema = z.object({
  keys: z.array(jwkSchema).min(1)
});
