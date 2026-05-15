import { z } from 'zod';

export const ECKey = z.object({
  crv: z.string(),
  kid: z.string().optional(),
  kty: z.literal('EC'),
  use: z.enum(['enc', 'sig']).optional(),
  x: z.string(),
  y: z.string()
});
export type ECKey = z.infer<typeof ECKey>;

export const ECPrivateKey = ECKey.extend({
  d: z.string()
});
export type ECPrivateKey = z.infer<typeof ECPrivateKey>;

export const RSAKey = z.object({
  alg: z.string().optional(),
  e: z.string(),
  kid: z.string().optional(),
  kty: z.literal('RSA'),
  n: z.string(),
  use: z.enum(['enc', 'sig']).optional()
});
export type RSAKey = z.infer<typeof RSAKey>;

export const RSAPrivateKey = RSAKey.extend({
  d: z.string(),
  dp: z.string().optional(),
  dq: z.string().optional(),
  p: z.string().optional(),
  q: z.string().optional(),
  qi: z.string().optional(),
  u: z.string().optional()
});
export type RSAPrivateKey = z.infer<typeof RSAPrivateKey>;

export const JwkPublicKey = z.discriminatedUnion('kty', [RSAKey, ECKey]);
export type JwkPublicKey = z.infer<typeof JwkPublicKey>;

export const JwkPrivateKey = z.discriminatedUnion('kty', [RSAPrivateKey, ECPrivateKey]);
export type JwkPrivateKey = z.infer<typeof JwkPrivateKey>;

export const Jwk = z.union([JwkPublicKey, JwkPrivateKey]);
export type Jwk = z.infer<typeof Jwk>;

export const JwksMetadata = z.object({
  keys: z.array(JwkPublicKey)
});
export type JwksMetadata = z.infer<typeof JwksMetadata>;

export const ECPrivateKeyWithKidCodec = ECPrivateKey.extend({
  kid: z.string()
});
export type ECPrivateKeyWithKid = z.infer<typeof ECPrivateKeyWithKidCodec>;
