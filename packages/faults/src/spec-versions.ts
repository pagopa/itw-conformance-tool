/**
 * IT Wallet specification versions the fault catalogs can reason about. Kept as
 * plain string literals (matching the `X-Spec-Version` header values used
 * across the Credential Issuer, see `spec-version.ts`) instead of importing
 * `@pagopa/io-wallet-utils`, so this package stays dependency-light.
 */
export const supportedItWalletSpecVersions = ['1.0', '1.3', '1.4'] as const;

export type SupportedItWalletSpecVersion = (typeof supportedItWalletSpecVersions)[number];

export function isSupportedItWalletSpecVersion(value: string): value is SupportedItWalletSpecVersion {
  return (supportedItWalletSpecVersions as readonly string[]).includes(value);
}
