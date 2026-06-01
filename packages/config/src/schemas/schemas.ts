import { z } from 'zod';

export const ConfigSchema = z.object({
  global: z
    .object({
      data_dir: z.string().min(1).catch('~/.itw-conformance-tool'),
      log_level: z.enum(['debug', 'info', 'warn', 'error']).catch('info')
    })
    .default({
      data_dir: '~/.itw-conformance-tool',
      log_level: 'info'
    }),
  'itw-credential-issuer': z
    .object({
      auth_flow: z.enum(['direct', 'l2plus', 'l3']).catch('direct'),
      port: z.coerce.number().int().min(1).max(65535).catch(3000),
      credential_types: z
        .string()
        .refine((s) => {
          const values = s
            .split(',')
            .map((v) => v.trim())
            .filter((v) => v.length > 0);
          const allowed = new Set(['pid', 'mdl', 'badge', 'eaa']);
          return values.length > 0 && values.every((v) => allowed.has(v)) && new Set(values).size === values.length;
        })
        .catch('pid,mdl,badge,eaa')
    })
    .default({
      auth_flow: 'direct',
      port: 3000,
      credential_types: 'pid,mdl,badge,eaa'
    }),
  rp: z
    .object({
      entity_id: z.string().url().catch(''),
      port: z.coerce.number().int().min(1).max(65535).catch(8080),
      trust_anchor: z.string().url().catch('')
    })
    .default({
      entity_id: '',
      port: 8080,
      trust_anchor: ''
    })
});

export const DEFAULT_CONFIG = ConfigSchema.parse({});
