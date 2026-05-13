import { ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { describe, expect, it } from 'vitest';

import { SPEC_VERSION_HEADER, SpecVersionError, resolveSpecVersionFromHeaders } from '../spec-version.js';

describe('resolveSpecVersionFromHeaders', () => {
  it('returns V1_0 when header is absent', () => {
    const headers = new Headers();

    expect(resolveSpecVersionFromHeaders(headers)).toBe(ItWalletSpecsVersion.V1_0);
  });

  it('returns V1_0 for header value "1.0"', () => {
    const headers = new Headers({ [SPEC_VERSION_HEADER]: '1.0' });

    expect(resolveSpecVersionFromHeaders(headers)).toBe(ItWalletSpecsVersion.V1_0);
  });

  it('returns V1_3 for header value "1.3"', () => {
    const headers = new Headers({ [SPEC_VERSION_HEADER]: '1.3' });

    expect(resolveSpecVersionFromHeaders(headers)).toBe(ItWalletSpecsVersion.V1_3);
  });

  it('throws SpecVersionError for unsupported version', () => {
    const headers = new Headers({ [SPEC_VERSION_HEADER]: '99.0' });

    expect(() => resolveSpecVersionFromHeaders(headers)).toThrow(SpecVersionError);
  });

  it('throws SpecVersionError with descriptive message', () => {
    const headers = new Headers({ [SPEC_VERSION_HEADER]: 'unsupported' });

    expect(() => resolveSpecVersionFromHeaders(headers)).toThrow(
      /Unsupported X-Spec-Version header value/,
    );
  });
});
