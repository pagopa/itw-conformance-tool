import { DataItem, cborDecode, cborEncode } from "@owf/mdoc";
import { createHash } from "crypto";
import { calculateJwkThumbprint } from "jose";
import { describe, expect, it } from "vitest";

import { createOid4VpSessionTranscript } from "../utils";

describe("createOid4VpSessionTranscript", () => {
  it("builds the OpenID4VP handover transcript for encrypted responses", async () => {
    const verifierEncryptionPublicJwk = {
      crv: "P-256",
      kid: "enc-kid",
      kty: "EC",
      x: "f83OJ3D2xF4zYf1XjzQ0rQm_xT1Z4qVakiobP6KyHRc",
      y: "x_FEzRu9Nta_yVxDSHLVYRIlnJrped1IovnEwlHGhEq",
    } as const;

    const transcript = await createOid4VpSessionTranscript({
      clientId: "x509_hash:https://issuer.example",
      handoverUri: "https://issuer.example/presentation-response",
      nonce: "nonce-123",
      verifierEncryptionPublicJwk,
    });

    const thumbprint = await calculateJwkThumbprint(
      verifierEncryptionPublicJwk,
    );
    const thumbprintBytes = new Uint8Array(
      Buffer.from(thumbprint, "base64url"),
    );
    const expectedHandoverInfo = [
      "x509_hash:https://issuer.example",
      "nonce-123",
      thumbprintBytes,
      "https://issuer.example/presentation-response",
    ];
    const expectedHash = new Uint8Array(
      createHash("sha256")
        .update(cborEncode(DataItem.fromData(expectedHandoverInfo)))
        .digest(),
    );

    expect(cborDecode(transcript)).toEqual([
      null,
      null,
      ["OpenID4VPHandover", expectedHash],
    ]);
  });

  it("uses null as the JWK thumbprint when no verifier key is provided", async () => {
    const transcript = await createOid4VpSessionTranscript({
      clientId: "client-id",
      handoverUri: "https://issuer.example/redirect",
      nonce: "nonce-123",
    });

    const expectedHandoverInfo = [
      "client-id",
      "nonce-123",
      null,
      "https://issuer.example/redirect",
    ];
    const expectedHash = new Uint8Array(
      createHash("sha256")
        .update(cborEncode(DataItem.fromData(expectedHandoverInfo)))
        .digest(),
    );

    expect(cborDecode(transcript)).toEqual([
      null,
      null,
      ["OpenID4VPHandover", expectedHash],
    ]);
  });
});
