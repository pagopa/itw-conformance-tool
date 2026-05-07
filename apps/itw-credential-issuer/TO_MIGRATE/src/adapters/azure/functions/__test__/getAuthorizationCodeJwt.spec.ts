import type { ParRequestRepository } from "@/domain/par";
import type { JwksRepository } from "@/domain/signer";
import type {
  HttpRequest,
  HttpResponseInit,
  InvocationContext,
} from "@azure/functions";

import { randomUUID } from "crypto";
import { SignJWT, importJWK } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GetAuthorizationCodeJwtHandler } from "../get-authorization-code-jwt";

vi.mock("crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("crypto")>();
  return {
    ...actual,
    randomUUID: vi.fn(),
  };
});

vi.mock("jose", () => ({
  SignJWT: vi.fn(),
  importJWK: vi.fn(),
}));

vi.mock("@/domain/utils/form_post_jwt", () => ({
  getFormPostFromRedirectUriAndJwt: vi.fn(() => "<html>form post</html>"),
}));

const mockParRequestRepository: ParRequestRepository = {
  consumeByCode: vi.fn(),
  get: vi.fn(),
  insert: vi.fn(),
  update: vi.fn(),
};

const mockJwkRepository: JwksRepository = {
  getEncrypt: vi.fn(),
  getSign: vi.fn().mockReturnValue({
    private: { kid: "sig-kid", kty: "EC" },
    public: { kid: "sig-kid", kty: "EC" },
  }),
  iacaX509: vi.fn(),
};

describe("GetAuthorizationCodeJwtHandler", () => {
  const mockContext: InvocationContext = {
    app: {
      config: {
        baseURL: "https://issuer.example.com",
      },
      repository: {
        jwks: mockJwkRepository,
        par: mockParRequestRepository,
      },
    },
    error: vi.fn(),
    log: vi.fn(),
  } as unknown as InvocationContext;

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it("should update the PAR with code timestamps for EAA", async () => {
    vi.mocked(randomUUID).mockReturnValue(
      "22222222-2222-2222-2222-222222222222",
    );
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);
    vi.mocked(importJWK).mockResolvedValue("imported-sig" as never);
    vi.mocked(mockParRequestRepository.get).mockResolvedValue({
      authorization_details: [
        {
          credential_configuration_id: "dc_sd_jwt_EuropeanDisabilityCard",
          type: "openid_credential",
        },
      ],
      client_id: "test_client",
      redirect_uri: "https://client.example/callback",
      request_uri: "urn:ietf:params:oauth:request_uri:test",
      state: "test_state",
    } as never);
    vi.mocked(mockParRequestRepository.update).mockResolvedValue();

    const sign = vi.fn().mockResolvedValue("signed-jwt");
    const setProtectedHeader = vi.fn().mockReturnValue({ sign });
    const setExpirationTime = vi.fn().mockReturnValue({ setProtectedHeader });
    const setIssuedAt = vi.fn().mockReturnValue({ setExpirationTime });
    const setIssuer = vi.fn().mockReturnValue({ setIssuedAt });

    vi.mocked(SignJWT).mockImplementation(
      () =>
        ({
          setIssuer,
        }) as never,
    );

    const mockRequest = {
      query: new Map([
        ["request_uri", "urn:ietf:params:oauth:request_uri:test"],
      ]),
    } as unknown as HttpRequest;

    const response: HttpResponseInit = await GetAuthorizationCodeJwtHandler(
      mockRequest,
      mockContext,
    );

    expect(response.status).toBe(200);
    expect(response.body).toBe("<html>form post</html>");
    expect(mockParRequestRepository.update).toHaveBeenCalledWith(
      expect.objectContaining({
        code: "22222222-2222-2222-2222-222222222222",
        code_expires_at: 1_700_000_300,
      }),
    );
    expect(setExpirationTime).toHaveBeenCalledWith("5m");
    expect(sign).toHaveBeenCalledWith("imported-sig");
  });
});
