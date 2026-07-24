import { ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';

export const SPEC_VERSION_HEADER = 'X-Spec-Version';

const SPEC_VERSION_BY_HEADER = {
  '1.0': ItWalletSpecsVersion.V1_0,
  '1.3': ItWalletSpecsVersion.V1_3,
  '1.4': ItWalletSpecsVersion.V1_4
} as const;

type SupportedSpecVersionHeader = keyof typeof SPEC_VERSION_BY_HEADER;

export class SpecVersionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SpecVersionError';
    Object.setPrototypeOf(this, SpecVersionError.prototype);
  }
}

export const resolveSpecVersionFromHeaders = (headers: Headers): ItWalletSpecsVersion => {
  const version = headers.get(SPEC_VERSION_HEADER);

  if (!version) {
    return ItWalletSpecsVersion.V1_3;
  }

  const normalizedVersion = version.trim() as SupportedSpecVersionHeader;
  const specVersion = SPEC_VERSION_BY_HEADER[normalizedVersion];

  if (!specVersion) {
    throw new SpecVersionError(`Unsupported ${SPEC_VERSION_HEADER} header value: ${version}`);
  }

  return specVersion;
};

const SPEC_VERSION_HEADER_BY_VALUE = new Map<ItWalletSpecsVersion, SupportedSpecVersionHeader>(
  Object.entries(SPEC_VERSION_BY_HEADER).map(([header, value]) => [value, header as SupportedSpecVersionHeader])
);

/**
 * Formats a resolved `ItWalletSpecsVersion` back to the `X-Spec-Version`
 * header string (e.g. `'1.4'`), for evidence and diagnostics that must
 * report the resolved specification version in the same format testers see
 * on the wire.
 */
export const formatSpecVersionHeader = (version: ItWalletSpecsVersion): string =>
  SPEC_VERSION_HEADER_BY_VALUE.get(version) ?? version;
