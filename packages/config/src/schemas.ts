import { z } from 'zod';

export const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export const ISSUER_AUTH_FLOWS = ['direct', 'l2plus', 'l3'] as const;
export const CREDENTIAL_TYPES = ['pid', 'mdl', 'badge', 'eaa'] as const;

export const DEFAULT_CONFIG = {
  global: {
    data_dir: '~/.itw-conformance-tool',
    log_level: 'info',
    wallet_provider_backend_url: 'https://wallet-provider-backend.example.com'
  },
  'itw-credential-issuer': {
    auth_flow: 'direct',
    port: 3000,
    credential_types: 'pid,mdl,badge,eaa',
    entity_id: 'https://localhost:3000'
  },
  rp: {
    port: 8080,
    entity_id: 'https://127.0.0.1:3000',
    trust_anchor_url: '/.well-known/openid-federation'
  },
  'itw-trust-anchor': {
    port: 3001,
    entity_id: 'https://localhost:3001'
  }
} as const;

const globalDefaults = DEFAULT_CONFIG.global;
const issuerDefaults = DEFAULT_CONFIG['itw-credential-issuer'];
const rpDefaults = DEFAULT_CONFIG.rp;
const trustAnchorDefaults = DEFAULT_CONFIG['itw-trust-anchor'];

export const ConfigIniTemplate = `[global]
; Local directory for keys, certificates, and generated data
; Default: ${globalDefaults.data_dir}
data_dir = ${globalDefaults.data_dir}
; Logging level: debug | info | warn | error
; Default: ${globalDefaults.log_level}
log_level = ${globalDefaults.log_level}
; Wallet Provider Backend URL (used for conformance tests)
wallet_provider_backend_url = ${globalDefaults.wallet_provider_backend_url}

[itw-credential-issuer]
; Authentication flow: direct | l2plus | l3
; Default: ${issuerDefaults.auth_flow}
auth_flow = ${issuerDefaults.auth_flow}
; HTTP port for the local issuer service
; Default: ${issuerDefaults.port}
port = ${issuerDefaults.port}
; Enabled credential types: pid | mdl | badge | eaa (comma-separated)
; Default: ${issuerDefaults.credential_types}
credential_types = ${issuerDefaults.credential_types}
; Issuer OpenID Federation Entity ID
; Example: https://issuer.example.org
entity_id = ${issuerDefaults.entity_id}

[rp]
; HTTP port for the local relying party service
; Default: ${rpDefaults.port}
port = ${rpDefaults.port}
; RP OpenID Federation Entity ID (leaf entity)
; Example: https://rp.example.org
entity_id = ${rpDefaults.entity_id}
; Trust Anchor URL for Federation validation
trust_anchor_url = ${rpDefaults.trust_anchor_url}

[itw-trust-anchor]
; HTTP port for the local trust anchor service
; Default: ${trustAnchorDefaults.port}
port = ${trustAnchorDefaults.port}
; Trust Anchor OpenID Federation Entity ID (trust anchor entity)
; Example: https://trust-anchor.example.org
entity_id = ${trustAnchorDefaults.entity_id}
`;

function trimLowercaseString(value: unknown): unknown {
  return typeof value === 'string' ? value.trim().toLowerCase() : value;
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

const allowedCredentialTypes = new Set<string>(CREDENTIAL_TYPES);

function isCredentialTypesList(value: string): boolean {
  const credentialTypes = value.split(',');
  return (
    credentialTypes.every((credentialType) => allowedCredentialTypes.has(credentialType)) &&
    new Set(credentialTypes).size === credentialTypes.length
  );
}

const nonEmptyString = z.string().trim().min(1);
const port = z.coerce.number().int().min(1).max(65535);

const GlobalConfigSchema = z
  .object({
    data_dir: nonEmptyString.default(globalDefaults.data_dir),
    log_level: z.preprocess(trimLowercaseString, z.enum(LOG_LEVELS)).default(globalDefaults.log_level),
    wallet_provider_backend_url: nonEmptyString.refine(isHttpsUrl).default(globalDefaults.wallet_provider_backend_url)
  })
  .default(globalDefaults);

const IssuerConfigSchema = z
  .object({
    auth_flow: z.preprocess(trimLowercaseString, z.enum(ISSUER_AUTH_FLOWS)).default(issuerDefaults.auth_flow),
    port: port.default(issuerDefaults.port),
    credential_types: z
      .preprocess(normalizeCredentialTypes, nonEmptyString)
      .refine(isCredentialTypesList)
      .default(issuerDefaults.credential_types),
    entity_id: nonEmptyString.default(issuerDefaults.entity_id)
  })
  .default(issuerDefaults);

const RpConfigSchema = z
  .object({
    port: port.default(rpDefaults.port),
    entity_id: nonEmptyString.default(rpDefaults.entity_id),
    trust_anchor_url: nonEmptyString.default(rpDefaults.trust_anchor_url)
  })
  .default(rpDefaults);

const TrustAnchorConfigSchema = z
  .object({
    port: port.default(trustAnchorDefaults.port),
    entity_id: nonEmptyString.default(trustAnchorDefaults.entity_id)
  })
  .default(trustAnchorDefaults);

export const ConfigSchema = z.object({
  global: GlobalConfigSchema,
  'itw-credential-issuer': IssuerConfigSchema,
  rp: RpConfigSchema,
  'itw-trust-anchor': TrustAnchorConfigSchema
});

export type ConfigSchemaType = z.infer<typeof ConfigSchema>;
export type LogLevel = (typeof LOG_LEVELS)[number];
export type IssuerAuthFlow = (typeof ISSUER_AUTH_FLOWS)[number];
export type CredentialType = (typeof CREDENTIAL_TYPES)[number];
