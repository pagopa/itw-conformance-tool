import { z } from 'zod';

const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
const ISSUER_AUTH_FLOWS = ['direct', 'l2plus', 'l3'] as const;
const CREDENTIAL_TYPES = ['pid', 'mdl', 'badge', 'eaa'] as const;

export const DEFAULT_CONFIG = {
  global: {
    data_dir: '~/.itw-conformance-tool',
    log_level: 'info',
    https: true,
    wallet_provider_backend_url: 'https://127.0.0.1:8080'
  },
  'itw-credential-issuer': {
    auth_flow: 'direct',
    port: 3000,
    credential_types: 'pid,mdl,badge,eaa'
  },
  rp: {
    port: 8080,
    entity_id: 'https://127.0.0.1:3000',
    trust_anchor_url: '/.well-known/openid-federation'
  }
} as const;

export const ConfigIniTemplate = `[global]
; Local directory for keys, certificates, and generated data
; Default: ${DEFAULT_CONFIG.global.data_dir}
data_dir = ${DEFAULT_CONFIG.global.data_dir}
; Logging level: debug | info | warn | error
; Default: ${DEFAULT_CONFIG.global.log_level}
log_level = ${DEFAULT_CONFIG.global.log_level}
; Enable HTTPS mode (CLI generates/checks local TLS cert/key and forwards ITW_CT_HTTPS) (true | false)
; Default: ${DEFAULT_CONFIG.global.https}
https = ${DEFAULT_CONFIG.global.https}
; Wallet Provider Backend URL (used for conformance tests)
; Default: ${DEFAULT_CONFIG.global.wallet_provider_backend_url}
wallet_provider_backend_url = ${DEFAULT_CONFIG.global.wallet_provider_backend_url}

[itw-credential-issuer]
; Authentication flow: direct | l2plus | l3
; Default: ${DEFAULT_CONFIG['itw-credential-issuer'].auth_flow}
auth_flow = ${DEFAULT_CONFIG['itw-credential-issuer'].auth_flow}
; HTTP port for the issuer service
; Default: ${DEFAULT_CONFIG['itw-credential-issuer'].port}
port = ${DEFAULT_CONFIG['itw-credential-issuer'].port}
; Enabled credential types: pid | mdl | badge | eaa (comma-separated)
; Default: ${DEFAULT_CONFIG['itw-credential-issuer'].credential_types}
credential_types = ${DEFAULT_CONFIG['itw-credential-issuer'].credential_types}

[rp]
; HTTP port for the itw-relying-party service
; Default: ${DEFAULT_CONFIG.rp.port}
port = ${DEFAULT_CONFIG.rp.port}
; RP OpenID Federation Entity ID (leaf entity)
; Example: https://rp.example.org
entity_id = ${DEFAULT_CONFIG.rp.entity_id}
; Trust Anchor URL for Federation validation
; Override with env: ITW_CT_RP_TRUST_ANCHOR_URL
trust_anchor_url = ${DEFAULT_CONFIG.rp.trust_anchor_url}
`;

function parseBoolean(value: unknown): unknown {
  if (typeof value !== 'string') {
    return value;
  }

  const normalized = value.trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['false', '0', 'no', 'off'].includes(normalized)) {
    return false;
  }

  return value;
}

function normalizeCredentialTypes(value: unknown): unknown {
  if (typeof value !== 'string') {
    return value;
  }

  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
    .join(',');
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

const credentialTypeSet = new Set<string>(CREDENTIAL_TYPES);
const nonEmptyString = z.string().trim().min(1);
const port = z.coerce.number().int().min(1).max(65535);

export type ConfigSchemaType = z.infer<typeof ConfigSchema>;

export const ConfigSchema = z.object({
  global: z
    .object({
      data_dir: nonEmptyString.default(DEFAULT_CONFIG.global.data_dir),
      log_level: z
        .preprocess((value) => (typeof value === 'string' ? value.trim().toLowerCase() : value), z.enum(LOG_LEVELS))
        .default(DEFAULT_CONFIG.global.log_level),
      https: z.preprocess(parseBoolean, z.boolean()).default(DEFAULT_CONFIG.global.https),
      wallet_provider_backend_url: nonEmptyString
        .refine(isHttpsUrl)
        .default(DEFAULT_CONFIG.global.wallet_provider_backend_url)
    })
    .default(DEFAULT_CONFIG.global),
  'itw-credential-issuer': z
    .object({
      auth_flow: z
        .preprocess(
          (value) => (typeof value === 'string' ? value.trim().toLowerCase() : value),
          z.enum(ISSUER_AUTH_FLOWS)
        )
        .default(DEFAULT_CONFIG['itw-credential-issuer'].auth_flow),
      port: port.default(DEFAULT_CONFIG['itw-credential-issuer'].port),
      credential_types: z
        .preprocess(normalizeCredentialTypes, nonEmptyString)
        .refine((value) => {
          const credentialTypes = value.split(',');
          return (
            credentialTypes.every((credentialType) => credentialTypeSet.has(credentialType)) &&
            new Set(credentialTypes).size === credentialTypes.length
          );
        })
        .default(DEFAULT_CONFIG['itw-credential-issuer'].credential_types)
    })
    .default(DEFAULT_CONFIG['itw-credential-issuer']),
  rp: z
    .object({
      port: port.default(DEFAULT_CONFIG.rp.port),
      entity_id: nonEmptyString.default(DEFAULT_CONFIG.rp.entity_id),
      trust_anchor_url: nonEmptyString.default(DEFAULT_CONFIG.rp.trust_anchor_url)
    })
    .default(DEFAULT_CONFIG.rp)
});
