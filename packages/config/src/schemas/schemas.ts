import { z } from 'zod';

export const ConfigINITemplate = `[global]
; Local directory for keys, certificates, and generated data
; Default: ~/.itw-conformance-tool
data_dir = ~/.itw-conformance-tool
; Logging level: debug | info | warn | error
; Default: info
log_level = info
; Enable HTTPS mode (CLI generates/checks local TLS cert/key and forwards ITW_CT_HTTPS) (true | false)
; Default: true
https = true

[itw-credential-issuer]
; Authentication flow: direct | l2plus | l3
; Default: direct
auth_flow = direct
; HTTP port for the issuer service
; Default: 3000
port = 3000
; Enabled credential types: pid | mdl | badge | eaa (comma-separated)
; Default: pid,mdl,badge,eaa
credential_types = pid,mdl,badge,eaa

[rp]
; HTTP port for the itw-relying-party service
; Default: 8080
port = 8080
; RP OpenID Federation Entity ID (leaf entity)
; Example: https://rp.example.org
entity_id =
; Trust Anchor URL for Federation validation
; Override with env: ITW_CT_RP_TRUST_ANCHOR_URL
trust_anchor_url = 
; Path to the x5c certificate chain PEM file of the RP 
; Override with env: ITW_CT_RP_X5C_CERT_PATH
; Default: ~/.itw-conformance-tool/rp/x5c-cert.pem
x5c_cert_path = ~/.itw-conformance-tool/rp/x5c-cert.pem
`;

export const ConfigSchema = z.object({
  global: z
    .object({
      data_dir: z.string().min(1).catch('~/.itw-conformance-tool'),
      log_level: z.enum(['debug', 'info', 'warn', 'error']).catch('info'),
      https: z.boolean().default(false)
    })
    .default({
      data_dir: '~/.itw-conformance-tool',
      log_level: 'info',
      https: false
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
      port: z.coerce.number().int().min(1).max(65535).catch(8080),
      entity_id: z.string().url().catch(''),
      trust_anchor_url: z.string().catch(''),
      x5c_cert_path: z.string().catch('~/.itw-conformance-tool/rp/x5c-cert.pem')
    })
    .default({
      port: 8080,
      entity_id: '',
      trust_anchor_url: '',
      x5c_cert_path: '~/.itw-conformance-tool/rp/x5c-cert.pem'
    })
});

export const DEFAULT_CONFIG = ConfigSchema.parse({});
