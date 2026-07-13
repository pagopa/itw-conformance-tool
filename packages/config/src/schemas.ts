import { z } from 'zod';

export const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export const ISSUER_AUTH_FLOWS = ['direct', 'l2plus', 'l3'] as const;
export const CREDENTIAL_TYPES = ['pid', 'mdl', 'badge', 'eaa'] as const;

export const DEFAULT_CONFIG = {
  global: {
    data_dir: '~/.itw-conformance-tool',
    log_level: 'info'
  },
  'wallet-provider': {
    url: 'https://wallet-provider-backend.example.com'
  },
  'credential-issuer': {
    url: 'https://127.0.0.1:3000',
    auth_flow: 'direct',
    credential_types: 'pid,mdl,badge,eaa'
  },
  'relying-party': {
    url: 'https://127.0.0.1:8080',
    entity_id: 'https://127.0.0.1:3000',
    trust_anchor_url: '/.well-known/openid-federation'
  }
} as const;

const globalDefaults = DEFAULT_CONFIG.global;
const walletProviderDefaults = DEFAULT_CONFIG['wallet-provider'];
const issuerDefaults = DEFAULT_CONFIG['credential-issuer'];
const rpDefaults = DEFAULT_CONFIG['relying-party'];

export const ConfigIniTemplate = `[global]
; Local directory for keys, certificates, and generated data
; Default: ${globalDefaults.data_dir}
data_dir = ${globalDefaults.data_dir}
; Logging level: debug | info | warn | error
; Default: ${globalDefaults.log_level}
log_level = ${globalDefaults.log_level}

[wallet-provider]
; Wallet Provider Backend URL (used for conformance tests)
; You need to set this to the URL of your wallet provider backend for the conformance tests to work.
url = ${walletProviderDefaults.url}

[credential-issuer]
; Local Credential Issuer URL (used for conformance tests)
url = ${issuerDefaults.url}
; Authentication flow: direct | l2plus | l3
; Default: ${issuerDefaults.auth_flow}
auth_flow = ${issuerDefaults.auth_flow}
; Enabled credential types: pid | mdl | badge | eaa (comma-separated)
; Default: ${issuerDefaults.credential_types}
credential_types = ${issuerDefaults.credential_types}

[relying-party]
; Local Relying Party Backend URL (used for conformance tests)
url = ${rpDefaults.url}
; RP OpenID Federation Entity ID (leaf entity)
; Example: https://rp.example.org
entity_id = ${rpDefaults.entity_id}
; Trust Anchor URL for Federation validation
trust_anchor_url = ${rpDefaults.trust_anchor_url}
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

const allowedCredentialTypes = new Set<string>(CREDENTIAL_TYPES);

function isCredentialTypesList(value: string): boolean {
  const credentialTypes = value.split(',');
  return (
    credentialTypes.every((credentialType) => allowedCredentialTypes.has(credentialType)) &&
    new Set(credentialTypes).size === credentialTypes.length
  );
}

const nonEmptyString = z.string().trim().min(1);

const GlobalConfigSchema = z
  .object({
    data_dir: nonEmptyString.default(globalDefaults.data_dir),
    log_level: z.preprocess(trimLowercaseString, z.enum(LOG_LEVELS)).default(globalDefaults.log_level)
  })
  .default(globalDefaults);

const WalletProviderConfigSchema = z
  .object({
    url: z.url({ protocol: /^https$/ }).default(walletProviderDefaults.url)
  })
  .default(walletProviderDefaults);

const IssuerConfigSchema = z
  .object({
    url: z.url({ protocol: /^https$/ }).default(issuerDefaults.url),
    auth_flow: z.preprocess(trimLowercaseString, z.enum(ISSUER_AUTH_FLOWS)).default(issuerDefaults.auth_flow),
    credential_types: z
      .preprocess(normalizeCredentialTypes, nonEmptyString)
      .refine(isCredentialTypesList)
      .default(issuerDefaults.credential_types)
  })
  .default(issuerDefaults);

const RpConfigSchema = z
  .object({
    url: z.url({ protocol: /^https$/ }).default(rpDefaults.url),
    entity_id: nonEmptyString.default(rpDefaults.entity_id),
    trust_anchor_url: nonEmptyString.default(rpDefaults.trust_anchor_url)
  })
  .default(rpDefaults);

export const ConfigSchema = z.object({
  global: GlobalConfigSchema,
  'wallet-provider': WalletProviderConfigSchema,
  'credential-issuer': IssuerConfigSchema,
  'relying-party': RpConfigSchema
});

export type ConfigSchemaType = z.infer<typeof ConfigSchema>;
export type LogLevel = (typeof LOG_LEVELS)[number];
export type IssuerAuthFlow = (typeof ISSUER_AUTH_FLOWS)[number];
export type CredentialType = (typeof CREDENTIAL_TYPES)[number];
