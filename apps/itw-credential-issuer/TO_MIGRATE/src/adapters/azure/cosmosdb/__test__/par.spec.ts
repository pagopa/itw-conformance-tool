import type { Database } from "@azure/cosmos";

import { InvalidGrantError } from "@/domain/token";
import { afterEach, describe, expect, it, vi } from "vitest";

import { makeParRequestRepository } from "../par";

const makeStoredParRequest = (overrides = {}) => ({
  _etag: "etag-1",
  authorization_details: [
    {
      credential_configuration_id: "dc_sd_jwt_PersonIdentificationData",
      type: "openid_credential",
    },
  ],
  client_id: "client_abc",
  clientId: "client_abc",
  code: "code123",
  code_challenge: "challenge123",
  code_challenge_method: "S256",
  exp: Math.floor(Date.now() / 1000) + 3600,
  id: "par-id",
  jti: "jti-123",
  redirect_uri: "https://client.example/callback",
  request_uri: "urn:ietf:params:oauth:request_uri:test",
  response_mode: "query",
  response_type: "vp_token",
  state: "test_state",
  ...overrides,
});

describe("makeParRequestRepository.consumeByCode", () => {
  const fetchAll = vi.fn();
  const replace = vi.fn();

  const db = {
    container: vi.fn(() => ({
      item: vi.fn(() => ({
        replace,
      })),
      items: {
        create: vi.fn(),
        query: vi.fn(() => ({
          fetchAll,
        })),
        upsert: vi.fn(),
      },
    })),
  } as unknown as Database;

  const repository = makeParRequestRepository(db);

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it("should reject codes without expiry metadata", async () => {
    fetchAll.mockResolvedValueOnce({
      resources: [makeStoredParRequest()],
    });

    const result = repository.consumeByCode("code123");

    await expect(result).rejects.toThrowError(InvalidGrantError);
    await expect(result).rejects.toThrowError(
      /Authorization code is missing expiry metadata: code123/,
    );
  });

  it("should reject expired codes", async () => {
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_100_000);
    fetchAll.mockResolvedValueOnce({
      resources: [
        makeStoredParRequest({
          code_expires_at: 1_700_000_000,
        }),
      ],
    });

    const result = repository.consumeByCode("code123");

    await expect(result).rejects.toThrowError(InvalidGrantError);
    await expect(result).rejects.toThrowError(
      /Authorization code has expired at: 1700000000/,
    );
  });

  it("should reject already consumed codes", async () => {
    fetchAll.mockResolvedValueOnce({
      resources: [
        makeStoredParRequest({
          code_consumed_at: 1_700_000_000,
          code_expires_at: 1_700_000_300,
        }),
      ],
    });

    await expect(repository.consumeByCode("code123")).rejects.toThrowError(
      /Authorization code has already been used: code123/,
    );
  });

  it("should mark a valid code as consumed", async () => {
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_100_000);
    const storedParRequest = makeStoredParRequest({
      code_expires_at: 1_700_000_300,
    });
    fetchAll.mockResolvedValueOnce({
      resources: [storedParRequest],
    });
    replace.mockResolvedValueOnce({
      resource: {
        ...storedParRequest,
        code_consumed_at: 1_700_000_100,
      },
    });

    const result = await repository.consumeByCode("code123");

    expect(replace).toHaveBeenCalledWith(
      expect.objectContaining({
        code_consumed_at: 1_700_000_100,
      }),
      expect.any(Object),
    );
    expect(result).toMatchObject({
      code: "code123",
      code_consumed_at: 1_700_000_100,
    });
  });
});
