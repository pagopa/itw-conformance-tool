import { z } from 'zod';

export const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export const ISSUER_AUTH_FLOWS = ['direct', 'l2plus', 'l3'] as const;
export const CREDENTIAL_TYPES = ['pid', 'mdl', 'badge', 'eaa'] as const;
const DEFAULT_TRUSTED_WALLET_PROVIDER_ISSUERS = [
  'https://wallet-provider.example',
  'https://wallet-provider.wct.example:3002',
  'https://wallet-provider.wct.example.org:3002'
] as const;

export const DEFAULT_CONFIG = {
  global: {
    data_dir: '.itw-conformance-tool',
    log_level: 'info'
  },
  wallet: {
    wallet_name: 'IT Wallet Conformance Tool',
    wallet_version: 'V1_4'
  },
  'wallet-provider': {
    url: 'https://wallet-provider-backend.example.com'
  },
  'credential-issuer': {
    url: 'https://127.0.0.1:3000',
    auth_flow: 'direct',
    credential_types: 'pid,mdl,badge,eaa',
    credential_identifiers: '',
    batch_issuance_by_deferred: false,
    trusted_wallet_provider_issuers: DEFAULT_TRUSTED_WALLET_PROVIDER_ISSUERS.join(','),
    trust_anchor_url: 'https://localhost:3001'
  },
  'relying-party': {
    url: 'https://127.0.0.1:3002',
    entity_id: 'https://127.0.0.1:3002',
    trust_anchor_url: 'https://localhost:3001'
  },
  'trust-anchor': {
    url: 'https://127.0.0.1:3001',
    entity_id: 'https://localhost:3001'
  }
} as const;

const globalDefaults = DEFAULT_CONFIG.global;
const walletDefaults = DEFAULT_CONFIG.wallet;
const walletProviderDefaults = DEFAULT_CONFIG['wallet-provider'];
const issuerDefaults = DEFAULT_CONFIG['credential-issuer'];
const rpDefaults = DEFAULT_CONFIG['relying-party'];
const trustAnchorDefaults = DEFAULT_CONFIG['trust-anchor'];

export const ConfigIniTemplate = `[global]
; Local directory for keys, certificates, and generated data
; Default: ${globalDefaults.data_dir}
data_dir = ${globalDefaults.data_dir}
; Logging level: debug | info | warn | error
; Default: ${globalDefaults.log_level}
log_level = ${globalDefaults.log_level}

[wallet]
; Wallet name (used in conformance test reports)
; Default: ${walletDefaults.wallet_name}
wallet_name = ${walletDefaults.wallet_name}
; Wallet version (used in conformance test reports)
; Default: ${walletDefaults.wallet_version}
wallet_version = ${walletDefaults.wallet_version}

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
; Credential configuration IDs to expose as a scannable Credential Offer QR code on startup (comma-separated).
; Each ID must match a key of the issuer's credential_configurations_supported metadata.
; Leave empty to keep startup unchanged (no QR page, no browser opened).
; Default: (empty)
credential_identifiers = ${issuerDefaults.credential_identifiers}
; Return batch (multi-proof) credential requests through the deferred endpoint instead of issuing them immediately.
; Only affects requests that include multiple proofs; single-proof requests are always issued immediately.
; Default: ${issuerDefaults.batch_issuance_by_deferred}
batch_issuance_by_deferred = ${issuerDefaults.batch_issuance_by_deferred}
; Trusted Wallet Provider issuer Entity IDs allowed in credential proof key attestations (comma-separated).
; Each issuer must be an absolute HTTPS URL and is matched exactly by the Credential Issuer.
; Default: ${issuerDefaults.trusted_wallet_provider_issuers}
trusted_wallet_provider_issuers = ${issuerDefaults.trusted_wallet_provider_issuers}
; Trust Anchor Entity ID used in the issuer's authority_hints
; Default: ${issuerDefaults.trust_anchor_url}
trust_anchor_url = ${issuerDefaults.trust_anchor_url}

[relying-party]
; Local Relying Party URL (used for conformance tests)
url = ${rpDefaults.url}
; RP OpenID Federation Entity ID (leaf entity)
; Example: https://rp.example.org
entity_id = ${rpDefaults.entity_id}
; Trust Anchor Entity ID used for Federation validation and authority_hints
; Default: ${rpDefaults.trust_anchor_url}
trust_anchor_url = ${rpDefaults.trust_anchor_url}

[trust-anchor]
; Local Trust Anchor URL (used for conformance tests)
url = ${trustAnchorDefaults.url}
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

function normalizeStrictBoolean(value: unknown): unknown {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
  }

  // Anything else (e.g. "yes", "1", "True ") is left untouched so z.boolean()
  // rejects it explicitly instead of relying on JavaScript truthiness.
  return value;
}

/**
 * Splits a comma-separated credential identifiers string into a trimmed,
 * non-empty list. Shared by the config schema, the CLI `--credential-identifiers`
 * flag, and the issuer's env override so all three follow the same rules.
 */
export function splitCredentialIdentifiers(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

/**
 * Checks that a list of credential identifiers has no duplicates. Identifiers
 * are case-sensitive because they are keys of `credential_configurations_supported`.
 */
export function hasNoDuplicateCredentialIdentifiers(identifiers: string[]): boolean {
  return new Set(identifiers).size === identifiers.length;
}

function normalizeCredentialIdentifiers(value: unknown): unknown {
  return typeof value === 'string' ? splitCredentialIdentifiers(value) : value;
}

function splitCommaSeparatedList(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function normalizeTrustedWalletProviderIssuers(value: unknown): unknown {
  return typeof value === 'string' ? splitCommaSeparatedList(value) : value;
}

function hasNoDuplicateItems(items: string[]): boolean {
  return new Set(items).size === items.length;
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

const WalletConfigSchema = z
  .object({
    wallet_name: nonEmptyString.default(walletDefaults.wallet_name),
    wallet_version: nonEmptyString.default(walletDefaults.wallet_version)
  })
  .default(walletDefaults);

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
      .default(issuerDefaults.credential_types),
    credential_identifiers: z
      .preprocess(normalizeCredentialIdentifiers, z.array(nonEmptyString))
      .refine(hasNoDuplicateCredentialIdentifiers, { message: 'Duplicate credential identifiers are not allowed' })
      .default([]),
    batch_issuance_by_deferred: z
      .preprocess(normalizeStrictBoolean, z.boolean())
      .default(issuerDefaults.batch_issuance_by_deferred),
    trusted_wallet_provider_issuers: z
      .preprocess(
        normalizeTrustedWalletProviderIssuers,
        z.array(z.url({ protocol: /^https$/ })).min(1, 'At least one trusted Wallet Provider issuer is required')
      )
      .refine(hasNoDuplicateItems, { message: 'Duplicate trusted Wallet Provider issuers are not allowed' })
      .default([...DEFAULT_TRUSTED_WALLET_PROVIDER_ISSUERS]),
    trust_anchor_url: nonEmptyString.default(issuerDefaults.trust_anchor_url)
  })
  // credential_identifiers defaults to [] (post-preprocess output type), not
  // issuerDefaults.credential_identifiers ('', the raw ini-string default).
  .default({
    ...issuerDefaults,
    credential_identifiers: [],
    trusted_wallet_provider_issuers: [...DEFAULT_TRUSTED_WALLET_PROVIDER_ISSUERS]
  });

const RpConfigSchema = z
  .object({
    url: z.url({ protocol: /^https$/ }).default(rpDefaults.url),
    entity_id: nonEmptyString.default(rpDefaults.entity_id),
    trust_anchor_url: nonEmptyString.default(rpDefaults.trust_anchor_url)
  })
  .default(rpDefaults);

const TrustAnchorConfigSchema = z
  .object({
    url: z.url({ protocol: /^https$/ }).default(trustAnchorDefaults.url),
    entity_id: nonEmptyString.default(trustAnchorDefaults.entity_id)
  })
  .default(trustAnchorDefaults);

export const ConfigSchema = z.object({
  global: GlobalConfigSchema,
  wallet: WalletConfigSchema,
  'wallet-provider': WalletProviderConfigSchema,
  'credential-issuer': IssuerConfigSchema,
  'relying-party': RpConfigSchema,
  'trust-anchor': TrustAnchorConfigSchema
});

export type ConfigSchemaType = z.infer<typeof ConfigSchema>;
export type LogLevel = (typeof LOG_LEVELS)[number];
export type IssuerAuthFlow = (typeof ISSUER_AUTH_FLOWS)[number];
export type CredentialType = (typeof CREDENTIAL_TYPES)[number];
