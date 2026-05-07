/* eslint-disable max-lines-per-function */
import { verifyTokenDPoP } from "@pagopa/io-wallet-oauth2";
import {
  createCredentialResponse,
  parseCredentialRequest,
  verifyCredentialRequestJwtProof,
} from "@pagopa/io-wallet-oid4vci";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CreateCredentialError, createCredential } from "../credential";
import { callbacks } from "../crypto";
import { NonceRepository } from "../nonce";
import { JwksRepository } from "../signer";

vi.mock("@pagopa/io-wallet-oid4vci", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oid4vci")>();
  return {
    ...actual,
    createCredentialResponse: vi.fn(),
    parseCredentialRequest: vi.fn(),
    verifyCredentialRequestJwtProof: vi.fn(),
  };
});

vi.mock("@pagopa/io-wallet-oauth2", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oauth2")>();
  return {
    ...actual,
    verifyTokenDPoP: vi.fn(),
  };
});

vi.mock("jose", async (importOriginal) => {
  const actual = await importOriginal<typeof import("jose")>();
  return {
    ...actual,
    decodeJwt: vi.fn(),
    decodeProtectedHeader: vi.fn(),
  };
});

vi.mock("../z-jwk", () => ({
  JwkPublicKey: {
    safeParse: vi
      .fn()
      .mockReturnValue({ data: { kid: "holder-kid" }, success: true }),
  },
}));

vi.mock("../credentials/pid", () => ({
  createPidCredential: vi.fn().mockResolvedValue("signed-sd-jwt"),
}));

describe("createCredential()", () => {
  const config = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
  });
  const configV13 = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
  });

  const nonceRepo = {
    delete: vi.fn().mockResolvedValue(undefined),
    get: vi.fn().mockResolvedValue("nonce-123"),
  };

  const jwksRepo = {
    getEncrypt: vi.fn(),
    getSign: vi.fn().mockReturnValue({
      private: {
        crv: "P-256",
        d: "mock-d",
        kid: "mock-kid",
        kty: "EC",
        x: "mock-x",
        y: "mock-y",
      },
      public: {
        crv: "P-256",
        kid: "mock-kid",
        kty: "EC",
        x: "mock-x",
        y: "mock-y",
      },
    }),
    iacaX509: vi.fn(),
  } as unknown as JwksRepository;

  const credentialBody = JSON.stringify({
    credential_identifier: "dc_sd_jwt_PersonIdentificationData",
    proofs: [{ jwt: "proof-jwt" }],
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("returns a credential response on the happy path", async () => {
    vi.mocked(decodeJwt).mockReset();
    vi.mocked(decodeProtectedHeader).mockReturnValue({
      jwk: { crv: "P-256", kty: "EC", x: "mock-x", y: "mock-y" },
    } as never);
    vi.mocked(parseCredentialRequest).mockReturnValue({
      accessToken: "my-access-token",
      credentialRequest: {
        credential_identifier: "dc_sd_jwt_PersonIdentificationData",
      },
      dpopProof: "dpop-jwt",
      proofs: [{ jwt: "proof-jwt" }],
    } as never);
    vi.mocked(verifyTokenDPoP).mockResolvedValue({} as never);
    vi.mocked(verifyCredentialRequestJwtProof).mockResolvedValue({
      header: { jwk: { kid: "holder-kid" } },
    } as never);
    vi.mocked(createCredentialResponse).mockResolvedValue({
      response: "credential-response",
    } as never);
    // First call decodes the access token; second call decodes the proof JWT.
    vi.mocked(decodeJwt)
      .mockReturnValueOnce({
        cnf: { jkt: "thumbprint-abc" },
        sub: "wallet-client-abc",
      })
      .mockReturnValueOnce({ nonce: "nonce-123" });
    const result = await createCredential({
      baseURL: "https://issuer.example",
      body: credentialBody,
      callbacks,
      config,
      headers: new Headers({
        authorization: "DPoP my-access-token",
        dpop: "proof-jwt",
      }),
      jwksRepository: jwksRepo,
      method: "POST",
      nonceRepository: nonceRepo as unknown as NonceRepository,
      url: "https://issuer.example/credential",
    });

    expect(result).toEqual({ response: "credential-response" });
    expect(parseCredentialRequest).toHaveBeenCalled();
    expect(verifyTokenDPoP).toHaveBeenCalledWith(
      expect.objectContaining({
        accessToken: "my-access-token",
        dpopJwt: "dpop-jwt",
        request: expect.objectContaining({ method: "POST" }),
      }),
    );
    expect(verifyCredentialRequestJwtProof).toHaveBeenCalled();
    expect(createCredentialResponse).toHaveBeenCalledWith(
      expect.objectContaining({
        flow: {
          credentials: [{ credential: "signed-sd-jwt" }],
        },
      }),
    );
  });

  it("passes trusted wallet provider issuers for V1_3 proof verification", async () => {
    vi.mocked(decodeJwt).mockReset();
    vi.mocked(decodeProtectedHeader).mockReturnValue({
      jwk: { crv: "P-256", kty: "EC", x: "mock-x", y: "mock-y" },
    } as never);
    vi.mocked(parseCredentialRequest).mockReturnValue({
      accessToken: "my-access-token",
      credentialRequest: {
        credential_identifier: "dc_sd_jwt_PersonIdentificationData",
      },
      dpopProof: "dpop-jwt",
      proofs: [{ jwt: "proof-jwt" }],
    } as never);
    vi.mocked(verifyTokenDPoP).mockResolvedValue({} as never);
    vi.mocked(verifyCredentialRequestJwtProof).mockResolvedValue({
      header: { jwk: { kid: "holder-kid" } },
      keyAttestation: {} as never,
    } as never);
    vi.mocked(createCredentialResponse).mockResolvedValue({
      response: "credential-response",
    } as never);
    vi.mocked(decodeJwt)
      .mockReturnValueOnce({
        cnf: { jkt: "thumbprint-abc" },
        sub: "wallet-client-abc",
      })
      .mockReturnValueOnce({ nonce: "nonce-123" });

    await createCredential({
      baseURL: "https://issuer.example",
      body: credentialBody,
      callbacks,
      config: configV13,
      headers: new Headers({
        authorization: "DPoP my-access-token",
        dpop: "proof-jwt",
      }),
      jwksRepository: jwksRepo,
      method: "POST",
      nonceRepository: nonceRepo as unknown as NonceRepository,
      url: "https://issuer.example/credential",
    });

    expect(verifyCredentialRequestJwtProof).toHaveBeenCalledWith(
      expect.objectContaining({
        config: configV13,
        trustedWalletProviderIssuers: [
          "https://wallet-provider.example",
          "https://wallet-provider.wct.example:3002",
        ],
      }),
    );
  });

  it("throws if the body is not valid JSON", async () => {
    await expect(
      createCredential({
        baseURL: "https://issuer.example",
        body: "{",
        callbacks,
        config,
        headers: new Headers({
          authorization: "DPoP my-access-token",
          dpop: "proof-jwt",
        }),
        jwksRepository: jwksRepo,
        method: "POST",
        nonceRepository: nonceRepo as unknown as NonceRepository,
        url: "https://issuer.example/credential",
      }),
    ).rejects.toThrow();
  });

  it("throws if nonce is missing in the proof JWT", async () => {
    vi.mocked(decodeJwt).mockReset();
    vi.mocked(decodeProtectedHeader).mockReturnValue({
      jwk: { crv: "P-256", kty: "EC", x: "mock-x", y: "mock-y" },
    } as never);
    vi.mocked(parseCredentialRequest).mockReturnValue({
      accessToken: "my-access-token",
      credentialRequest: {
        credential_identifier: "dc_sd_jwt_PersonIdentificationData",
      },
      dpopProof: "dpop-jwt",
      proofs: [{ jwt: "proof-jwt" }],
    } as never);
    vi.mocked(verifyTokenDPoP).mockResolvedValue({} as never);
    vi.mocked(decodeJwt)
      .mockReturnValueOnce({
        cnf: { jkt: "thumbprint-abc" },
        sub: "wallet-client-abc",
      })
      .mockReturnValueOnce({});

    await expect(
      createCredential({
        baseURL: "https://issuer.example",
        body: credentialBody,
        callbacks,
        config,
        headers: new Headers({
          authorization: "DPoP my-access-token",
          dpop: "proof-jwt",
        }),
        jwksRepository: jwksRepo,
        method: "POST",
        nonceRepository: nonceRepo as unknown as NonceRepository,
        url: "https://issuer.example/credential",
      }),
    ).rejects.toThrowError(CreateCredentialError);
  });

  it("throws when the nonce is not in the repository", async () => {
    vi.mocked(decodeJwt).mockReset();
    vi.mocked(decodeProtectedHeader).mockReturnValue({
      jwk: { crv: "P-256", kty: "EC", x: "mock-x", y: "mock-y" },
    } as never);
    vi.mocked(parseCredentialRequest).mockReturnValue({
      accessToken: "my-access-token",
      credentialRequest: {
        credential_identifier: "dc_sd_jwt_PersonIdentificationData",
      },
      dpopProof: "dpop-jwt",
      proofs: [{ jwt: "proof-jwt" }],
    } as never);
    vi.mocked(verifyTokenDPoP).mockResolvedValue({} as never);
    vi.mocked(decodeJwt)
      .mockReturnValueOnce({
        cnf: { jkt: "thumbprint-abc" },
        sub: "wallet-client-abc",
      })
      .mockReturnValueOnce({ nonce: "nonce-123" });
    nonceRepo.get.mockResolvedValue(undefined);

    await expect(
      createCredential({
        baseURL: "https://issuer.example",
        body: credentialBody,
        callbacks,
        config,
        headers: new Headers({
          authorization: "DPoP my-access-token",
          dpop: "proof-jwt",
        }),
        jwksRepository: jwksRepo,
        method: "POST",
        nonceRepository: nonceRepo as unknown as NonceRepository,
        url: "https://issuer.example/credential",
      }),
    ).rejects.toThrow("Expected nonce not found");
  });

  it("rejects a DPoP proof with htm=GET", async () => {
    vi.mocked(decodeJwt).mockReset();
    vi.mocked(decodeProtectedHeader).mockReturnValue({
      jwk: { crv: "P-256", kty: "EC", x: "mock-x", y: "mock-y" },
    } as never);
    vi.mocked(parseCredentialRequest).mockReturnValue({
      accessToken: "my-access-token",
      credentialRequest: {
        credential_identifier: "dc_sd_jwt_PersonIdentificationData",
      },
      dpopProof: "dpop-jwt-with-htm-get",
      proofs: [{ jwt: "proof-jwt" }],
    } as never);
    vi.mocked(decodeJwt)
      .mockReturnValueOnce({
        cnf: { jkt: "thumbprint-abc" },
        sub: "wallet-client-abc",
      })
      .mockReturnValueOnce({ nonce: "nonce-123" });
    vi.mocked(verifyTokenDPoP).mockRejectedValue(
      new Error("htm mismatch: expected POST, got GET"),
    );

    await expect(
      createCredential({
        baseURL: "https://issuer.example",
        body: credentialBody,
        callbacks,
        config,
        headers: new Headers({
          authorization: "DPoP my-access-token",
          dpop: "dpop-jwt-with-htm-get",
        }),
        jwksRepository: jwksRepo,
        method: "POST",
        nonceRepository: nonceRepo as unknown as NonceRepository,
        url: "https://issuer.example/credential",
      }),
    ).rejects.toThrow("htm mismatch: expected POST, got GET");

    expect(verifyTokenDPoP).toHaveBeenCalledWith(
      expect.objectContaining({
        accessToken: "my-access-token",
        dpopJwt: "dpop-jwt-with-htm-get",
        request: expect.objectContaining({ method: "POST" }),
      }),
    );
  });

  it("rejects a DPoP proof with a missing or wrong ath claim", async () => {
    vi.mocked(decodeJwt).mockReset();
    vi.mocked(decodeProtectedHeader).mockReturnValue({
      jwk: { crv: "P-256", kty: "EC", x: "mock-x", y: "mock-y" },
    } as never);
    vi.mocked(parseCredentialRequest).mockReturnValue({
      accessToken: "my-access-token",
      credentialRequest: {
        credential_identifier: "dc_sd_jwt_PersonIdentificationData",
      },
      dpopProof: "dpop-jwt-no-ath",
      proofs: [{ jwt: "proof-jwt" }],
    } as never);
    vi.mocked(decodeJwt)
      .mockReturnValueOnce({
        cnf: { jkt: "thumbprint-abc" },
        sub: "wallet-client-abc",
      })
      .mockReturnValueOnce({ nonce: "nonce-123" });
    vi.mocked(verifyTokenDPoP).mockRejectedValue(
      new Error(
        "Dpop jwt does not have a ath value, but expected ath value 'abc123'.",
      ),
    );

    await expect(
      createCredential({
        baseURL: "https://issuer.example",
        body: credentialBody,
        callbacks,
        config,
        headers: new Headers({
          authorization: "DPoP my-access-token",
          dpop: "dpop-jwt-no-ath",
        }),
        jwksRepository: jwksRepo,
        method: "POST",
        nonceRepository: nonceRepo as unknown as NonceRepository,
        url: "https://issuer.example/credential",
      }),
    ).rejects.toThrow("Dpop jwt does not have a ath value");

    expect(verifyTokenDPoP).toHaveBeenCalledWith(
      expect.objectContaining({
        accessToken: "my-access-token",
        dpopJwt: "dpop-jwt-no-ath",
      }),
    );
  });

  it("rejects a DPoP proof that exposes a private key", async () => {
    vi.mocked(decodeProtectedHeader).mockReturnValue({
      jwk: {
        crv: "P-256",
        d: "private-d",
        kty: "EC",
        x: "mock-x",
        y: "mock-y",
      },
    } as never);

    await expect(
      createCredential({
        baseURL: "https://issuer.example",
        body: credentialBody,
        callbacks,
        config,
        headers: new Headers({
          authorization: "DPoP my-access-token",
          dpop: "dpop-jwt",
        }),
        jwksRepository: jwksRepo,
        method: "POST",
        nonceRepository: nonceRepo as unknown as NonceRepository,
        url: "https://issuer.example/credential",
      }),
    ).rejects.toThrowError(
      "Private keys are not allowed in the DPoP Proof JWT!",
    );
  });
});
