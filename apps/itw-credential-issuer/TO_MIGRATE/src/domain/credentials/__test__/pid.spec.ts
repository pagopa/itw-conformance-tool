import type { DisclosureFrame } from "@sd-jwt/types";

import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FakeUser } from "../../faker";
import { createPidCredential } from "../pid";

const { issueMock } = vi.hoisted(() => ({
  issueMock: vi.fn(),
}));

vi.mock("@sd-jwt/sd-jwt-vc", () => ({
  SDJwtVcInstance: vi.fn().mockImplementation(() => ({
    issue: issueMock,
  })),
}));

vi.mock("@/domain/sd-jwt", () => ({
  createSRIHash: vi.fn().mockReturnValue("sri-hash"),
  createSignerVerifier: vi.fn().mockResolvedValue([vi.fn(), vi.fn()]),
}));

describe("createPidCredential()", () => {
  const mockFakeUser: FakeUser = {
    birthDate: "1990-12-15",
    birthPlace: "Rome (RM)",
    documentNumber: "ABCDEFGHIJKLMNOPQR",
    familyName: "Rossi",
    fiscalCode: "RSSMRA90T12H501U",
    givenName: "Mario",
    id: "pid-sub-123",
  };

  afterEach(() => {
    vi.clearAllMocks();
    issueMock.mockResolvedValue("signed-pid");
  });

  it("builds the V1_3 PID SD-JWT payload with the current IT fields", async () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
    });

    await createPidCredential(
      "https://issuer.example",
      {
        getSign: vi.fn().mockReturnValue({
          private: {
            kid: "issuer-kid",
          },
        }),
        iacaX509: vi.fn().mockReturnValue("mock-cert"),
      } as never,
      {
        crv: "P-256",
        kid: "holder-kid",
        kty: "EC",
        x: "holder-x",
        y: "holder-y",
      },
      config,
      mockFakeUser,
    );

    expect(issueMock).toHaveBeenCalledWith(
      expect.objectContaining({
        personal_administrative_number: "RSSMRA90T12H501U",
        sub: "pid-sub-123",
        vct: "urn:eudi:pid:it:1",
        "vct#integrity": "sri-hash",
        verification: {
          assurance_level: "high",
          trust_framework: "it_cie",
        },
      }),
      expect.objectContaining({
        _sd: expect.arrayContaining([
          "birthdate",
          "place_of_birth",
          "family_name",
          "date_of_expiry",
          "given_name",
          "nationalities",
          "personal_administrative_number",
          "iat",
          "sub",
          "verification",
        ]),
      }) as DisclosureFrame<Record<string, unknown>>,
      expect.any(Object),
    );
  });

  it("keeps the legacy V1_0 PID SD-JWT payload shape", async () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
    });

    await createPidCredential(
      "https://issuer.example",
      {
        getSign: vi.fn().mockReturnValue({
          private: {
            kid: "issuer-kid",
          },
        }),
        iacaX509: vi.fn().mockReturnValue("mock-cert"),
      } as never,
      {
        crv: "P-256",
        kid: "holder-kid",
        kty: "EC",
        x: "holder-x",
        y: "holder-y",
      },
      config,
      mockFakeUser,
    );

    expect(issueMock).toHaveBeenCalledWith(
      expect.objectContaining({
        birth_place: "Rome (RM)",
        personal_administrative_number: "RSSMRA90T12H501U",
        sub: "holder-kid",
      }),
      expect.objectContaining({
        _sd: expect.arrayContaining([
          "birth_place",
          "personal_administrative_number",
        ]),
      }) as DisclosureFrame<Record<string, unknown>>,
      expect.any(Object),
    );
  });
});
