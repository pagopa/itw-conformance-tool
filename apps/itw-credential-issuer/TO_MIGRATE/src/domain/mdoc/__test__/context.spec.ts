import { CoseKey } from "@owf/mdoc";
import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { mdocContext } from "../context";

const { validateCertificateChain } = vi.hoisted(() => ({
  validateCertificateChain: vi.fn(),
}));

vi.mock("../../utils/x509", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/x509")>();

  return {
    ...actual,
    validateCertificateChain,
  };
});

describe("mdocContext.cose.sign1.verify()", () => {
  it("verifies ES256 signatures encoded in IEEE P1363 format", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
    });
    const privateJwk = privateKey.export({ format: "jwk" });
    const publicJwk = publicKey.export({ format: "jwk" });
    const toBeSigned = Buffer.from("mdoc-sign1-payload");

    const signature = await mdocContext.cose.sign1.sign({
      key: CoseKey.fromJwk(privateJwk as Record<string, unknown>),
      toBeSigned,
    });

    await expect(
      mdocContext.cose.sign1.verify({
        key: CoseKey.fromJwk(publicJwk as Record<string, unknown>),
        sign1: {
          signature,
          toBeSigned,
        } as never,
      }),
    ).resolves.toBe(true);
  });
});

describe("mdocContext.x509.verifyCertificateChain()", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("passes the supplied validation date to certificate chain validation", async () => {
    const { mdocContext } = await import("../context");
    const now = new Date("2026-01-09T11:50:00.000Z");

    await mdocContext.x509.verifyCertificateChain({
      now,
      trustedCertificates: [new Uint8Array([1, 2, 3])],
      x5chain: [new Uint8Array([4, 5, 6])],
    });

    expect(validateCertificateChain).toHaveBeenCalledWith({
      now,
      trustedCertificates: [Uint8Array.from([1, 2, 3]).buffer],
      x5chain: [Uint8Array.from([4, 5, 6]).buffer],
    });
  });
});
