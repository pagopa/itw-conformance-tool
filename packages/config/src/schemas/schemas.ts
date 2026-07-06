import { z } from 'zod';

function isHttpsAbsoluteUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

export const GLOBAL_SECTION_DEFAULTS = {
  data_dir: '~/.itw-conformance-tool',
  log_level: 'info',
  https: true
} as const;

export const ISSUER_SECTION_DEFAULTS = {
  auth_flow: 'direct',
  port: 3000,
  credential_types: 'pid,mdl,badge,eaa'
} as const;

export const RP_SECTION_DEFAULTS = {
  port: 8080,
  entity_id: 'https://127.0.0.1:3000',
  trust_anchor_url: '/.well-known/openid-federation'
} as const;

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
; Mandatory Wallet Provider Backend URL (used for conformance tests)
wallet_provider_backend_url = 

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
entity_id = https://127.0.0.1:3000
; Trust Anchor URL for Federation validation
; Override with env: ITW_CT_RP_TRUST_ANCHOR_URL
trust_anchor_url = /.well-known/openid-federation
`;

export const ConfigSchema = z.object({
  global: z.preprocess(
    (input) => {
      if (input === undefined) {
        return GLOBAL_SECTION_DEFAULTS;
      }

      if (typeof input !== 'object' || input === null) {
        return input;
      }

      return {
        ...GLOBAL_SECTION_DEFAULTS,
        ...(input as Record<string, unknown>)
      };
    },
    z.object({
      data_dir: z.string().min(1).catch('~/.itw-conformance-tool'),
      log_level: z.enum(['debug', 'info', 'warn', 'error']).catch('info'),
      https: z.boolean().catch(true),
      wallet_provider_backend_url: z
        .string()
        .min(1)
        .refine((value) => isHttpsAbsoluteUrl(value))
    })
  ),
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
    .default(ISSUER_SECTION_DEFAULTS),
  rp: z
    .object({
      port: z.coerce.number().int().min(1).max(65535).catch(8080),
      entity_id: z.string().min(1).catch('https://127.0.0.1:3000'),
      trust_anchor_url: z.string().min(1).catch('/.well-known/openid-federation')
    })
    .default(RP_SECTION_DEFAULTS)
});

export const DEFAULT_CONFIG = {
  global: GLOBAL_SECTION_DEFAULTS,
  'itw-credential-issuer': ISSUER_SECTION_DEFAULTS,
  rp: RP_SECTION_DEFAULTS
} as const;
