import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import {
  SPEC_VERSION_HEADER,
  SpecVersionError,
  resolveSpecVersionFromHeaders,
} from "../spec-version";

describe("spec-version", () => {
  it("defaults missing header to V1_0", () => {
    expect(resolveSpecVersionFromHeaders(new Headers())).toBe(
      ItWalletSpecsVersion.V1_0,
    );
  });

  it("maps supported header values", () => {
    expect(
      resolveSpecVersionFromHeaders(
        new Headers({
          [SPEC_VERSION_HEADER]: "1.0",
        }),
      ),
    ).toBe(ItWalletSpecsVersion.V1_0);

    expect(
      resolveSpecVersionFromHeaders(
        new Headers({
          [SPEC_VERSION_HEADER]: "1.3",
        }),
      ),
    ).toBe(ItWalletSpecsVersion.V1_3);
  });

  it("rejects unsupported header values", () => {
    expect(() =>
      resolveSpecVersionFromHeaders(
        new Headers({
          [SPEC_VERSION_HEADER]: "2.0",
        }),
      ),
    ).toThrowError(SpecVersionError);
  });
});
