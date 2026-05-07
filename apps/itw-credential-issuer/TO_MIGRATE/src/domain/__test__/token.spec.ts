/* eslint-disable max-lines-per-function */
import { appContext } from "@/app/context";
import { getSdkConfig } from "@/domain/sdk-config";
import { JwksRepository } from "@/domain/signer";
import {
  createAccessTokenResponse,
  parseAccessTokenRequest,
  verifyAccessTokenRequest,
} from "@pagopa/io-wallet-oauth2";
import { HttpMethod, ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as openidFederation from "../openid-federation";
import { ParRequestRepository } from "../par";
import {
  InvalidGrantError,
  UnsupportedGrantTypeError,
  createAccessToken,
} from "../token";

vi.mock("@pagopa/io-wallet-oauth2", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oauth2")>();
  return {
    ...actual,
    createAccessTokenResponse: vi.fn(),
    parseAccessTokenRequest: vi.fn(),
    verifyAccessTokenRequest: vi.fn(),
  };
});

describe("createAccessToken", () => {
  let jwksRepository: JwksRepository;
  let parRequestRepository: ParRequestRepository;
  let baseURL: string;
  let getMock: ReturnType<typeof vi.fn>;
  let consumeByCodeMock: ReturnType<typeof vi.fn>;
  let tokenRequest: {
    bodyString: string;
    headers: Headers;
    method: HttpMethod;
    url: string;
  };

  beforeEach(() => {
    baseURL = "https://issuer.example.com";

    jwksRepository = {
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

    const credentialConfigurationId = "UniversityDegreeCredential";
    const mockParRequest = {
      authorization_details: [
        {
          credential_configuration_id: credentialConfigurationId,
          type: "openid_credential",
        },
      ],
      client_id: "client_abc",
      code: "code123",
      code_challenge: "challenge123",
      code_challenge_method: "S256",
      redirect_uri: "https://client/cb",
    };

    getMock = vi.fn().mockResolvedValue(mockParRequest);
    consumeByCodeMock = vi.fn().mockResolvedValue(mockParRequest);

    parRequestRepository = {
      consumeByCode: consumeByCodeMock,
      get: getMock,
      insert: vi.fn(),
      update: vi.fn(),
    } as unknown as ParRequestRepository;

    tokenRequest = {
      bodyString:
        "code=code123&code_verifier=verifier&grant_type=authorization_code&redirect_uri=https://client/cb",
      headers: new Headers({
        "content-type": "application/x-www-form-urlencoded",
        dpop: "mock-dpop-jwt",
      }),
      method: "POST" as HttpMethod,
      url: "https://issuer.example.com/token",
    };

    vi.spyOn(
      openidFederation,
      "getEntityConfigurationClaimsMetadata",
    ).mockImplementation(() => ({
      // @ts-expect-error mock metadata is intentionally partial
      oauth_authorization_server: {},
      openid_credential_issuer: {
        credential_configurations_supported: {
          // @ts-expect-error mock metadata is intentionally partial
          [credentialConfigurationId]: {},
        },
      },
    }));

    vi.mocked(parseAccessTokenRequest).mockReturnValue({
      accessTokenRequest: {},
      clientAttestation: undefined,
      dpop: { jwt: "DPoP_JWT" },
      grant: { grantType: "authorization_code" },
      pkceCodeVerifier: "code_verifier_123",
    } as never);

    vi.mocked(verifyAccessTokenRequest).mockResolvedValue({
      dpop: { jwk: jwksRepository.getSign().public },
    } as never);

    vi.mocked(createAccessTokenResponse).mockResolvedValue({
      access_token: "ACCESS_TOKEN",
      expires_in: 300,
      token_type: "Bearer",
    } as never);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const makeOptions = () => ({
    baseURL,
    callbacks: appContext.callbacks,
    config: getSdkConfig(ItWalletSpecsVersion.V1_0),
    jwksRepository,
    parRequestRepository,
    tokenRequest,
  });

  it("should create an access token response (happy path)", async () => {
    const response = await createAccessToken(makeOptions());

    expect(response).toEqual({
      access_token: "ACCESS_TOKEN",
      expires_in: 300,
      token_type: "Bearer",
    });
    expect(getMock).toHaveBeenCalledWith({ code: "code123" });
    expect(consumeByCodeMock).toHaveBeenCalledWith("code123");
    expect(parseAccessTokenRequest).toHaveBeenCalled();
    expect(verifyAccessTokenRequest).toHaveBeenCalled();
    expect(createAccessTokenResponse).toHaveBeenCalled();
  });

  it("should throw if a required field is missing", async () => {
    tokenRequest.bodyString =
      "code_verifier=verifier&grant_type=authorization_code&redirect_uri=https://client/cb";

    await expect(createAccessToken(makeOptions())).rejects.toThrowError(
      /code, code_verifier, grant_type and redirect_uri must be present!/,
    );
  });

  it("should throw if redirect_uri is missing from the token request", async () => {
    tokenRequest.bodyString =
      "code=code123&code_verifier=verifier&grant_type=authorization_code";

    await expect(createAccessToken(makeOptions())).rejects.toThrowError(
      /code, code_verifier, grant_type and redirect_uri must be present!/,
    );
    expect(getMock).not.toHaveBeenCalled();
    expect(consumeByCodeMock).not.toHaveBeenCalled();
  });

  it("should throw if no PAR is found for the code", async () => {
    getMock.mockRejectedValueOnce(
      new Error("No Pushed Authorization Request found for code: code123"),
    );

    const result = createAccessToken(makeOptions());

    await expect(result).rejects.toThrowError(InvalidGrantError);
    await expect(result).rejects.toThrowError(
      /No Pushed Authorization Request found for code: code123/,
    );
    expect(consumeByCodeMock).not.toHaveBeenCalled();
  });

  it("should throw if the authorization code has already been used", async () => {
    consumeByCodeMock.mockRejectedValueOnce(
      new InvalidGrantError(
        "Authorization code has already been used: code123",
      ),
    );

    const result = createAccessToken(makeOptions());

    await expect(result).rejects.toThrowError(InvalidGrantError);
    await expect(result).rejects.toThrowError(
      /Authorization code has already been used: code123/,
    );
  });

  it("should throw if the authorization code has expired", async () => {
    consumeByCodeMock.mockRejectedValueOnce(
      new InvalidGrantError("Authorization code has expired (age: 61s)"),
    );

    const result = createAccessToken(makeOptions());

    await expect(result).rejects.toThrowError(InvalidGrantError);
    await expect(result).rejects.toThrowError(
      /Authorization code has expired \(age: 61s\)/,
    );
  });

  it("should throw if the grant type is not supported", async () => {
    vi.mocked(parseAccessTokenRequest).mockReturnValueOnce({
      accessTokenRequest: {
        grant_type: "refresh_token",
      },
      clientAttestation: undefined,
      dpop: { jwt: "DPoP_JWT" },
      grant: { grantType: "refresh_token" },
      pkceCodeVerifier: "code_verifier_123",
    } as never);

    const result = createAccessToken(makeOptions());

    await expect(result).rejects.toThrowError(UnsupportedGrantTypeError);
    await expect(result).rejects.toThrowError(
      /Unsupported grant type: refresh_token/,
    );
    expect(consumeByCodeMock).not.toHaveBeenCalled();
  });

  it("should throw InvalidGrantError if redirect_uri does not match PAR value", async () => {
    getMock.mockResolvedValueOnce({
      authorization_details: [
        {
          credential_configuration_id: "UniversityDegreeCredential",
          type: "openid_credential",
        },
      ],
      client_id: "client_abc",
      code: "code123",
      code_challenge: "challenge123",
      code_challenge_method: "S256",
      redirect_uri: "https://other-client/cb",
    });

    const result = createAccessToken(makeOptions());

    await expect(result).rejects.toThrowError(InvalidGrantError);
    await expect(result).rejects.toThrowError(/redirect_uri mismatch/);
    expect(consumeByCodeMock).not.toHaveBeenCalled();
  });

  it("should consume the authorization code after all validations and before creating the access token response", async () => {
    const response = await createAccessToken(makeOptions());

    expect(response).toEqual({
      access_token: "ACCESS_TOKEN",
      expires_in: 300,
      token_type: "Bearer",
    });
    expect(consumeByCodeMock.mock.invocationCallOrder[0]).toBeGreaterThan(
      vi.mocked(verifyAccessTokenRequest).mock.invocationCallOrder[0],
    );
    expect(consumeByCodeMock.mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(createAccessTokenResponse).mock.invocationCallOrder[0],
    );
  });
});
