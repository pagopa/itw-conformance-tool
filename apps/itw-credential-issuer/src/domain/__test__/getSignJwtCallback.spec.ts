import type { JwtSigner } from "@pagopa/io-wallet-oauth2";

import { makeJwksRepository } from "@/adapters/in-memory/signer";
import { config } from "@/app/config";
import { importJWK, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";

import { getSignJwtCallback } from "../crypto";

const jwksRepository = makeJwksRepository(
  config.signer.jwks,
  config.encrypter.jwks,
  config.cert.iacaX509,
);
const { private: privateSig, public: publicSig } = jwksRepository.getSign();
const x5cSigner: Extract<JwtSigner, { method: "x5c" }> = {
  alg: "ES256",
  kid: publicSig.kid,
  method: "x5c",
  x5c: [jwksRepository.iacaX509()],
};

describe("getSignJwtCallback", () => {
  it("signs JWTs when the signer method is x5c", async () => {
    const signJwt = getSignJwtCallback([privateSig]);
    const result = await signJwt(x5cSigner, {
      header: {
        alg: x5cSigner.alg,
        kid: publicSig.kid,
        typ: "oauth-authz-req+jwt",
        x5c: x5cSigner.x5c,
      },
      payload: {
        iss: "https://issuer.example.com",
        sub: "subject",
      },
    });

    const publicKey = await importJWK(publicSig, x5cSigner.alg);
    const { payload, protectedHeader } = await jwtVerify(result.jwt, publicKey);

    expect(result.signerJwk).toMatchObject({
      crv: publicSig.crv,
      kid: publicSig.kid,
      kty: publicSig.kty,
      x: publicSig.x,
      y: publicSig.y,
    });
    expect(protectedHeader.kid).toBe(publicSig.kid);
    expect(protectedHeader.typ).toBe("oauth-authz-req+jwt");
    expect(protectedHeader.x5c).toEqual(x5cSigner.x5c);
    expect(payload.iss).toBe("https://issuer.example.com");
    expect(payload.sub).toBe("subject");
  });

  it("throws when no private key matches the x5c signer kid", async () => {
    const signJwt = getSignJwtCallback([]);

    await expect(
      signJwt(x5cSigner, {
        header: {
          alg: x5cSigner.alg,
          kid: publicSig.kid,
          typ: "oauth-authz-req+jwt",
          x5c: x5cSigner.x5c,
        },
        payload: {
          iss: "https://issuer.example.com",
        },
      }),
    ).rejects.toThrow("No private key available for public jwk");
  });
});
