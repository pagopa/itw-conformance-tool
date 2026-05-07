import {
  zAuthorizationRequestV1_0,
  zAuthorizationRequestV1_3,
} from "@pagopa/io-wallet-oauth2";
import { zOpenid4vpAuthorizationRequestPayload } from "@pagopa/io-wallet-oid4vp";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

const WithCustomClaims = z.object({
  code: z.string().optional(), // The authorization code returned by the authorization server
  code_consumed_at: z.number().optional(), // Unix timestamp (seconds) when the authorization code was consumed
  code_expires_at: z.number().optional(), // Unix timestamp (seconds) when the authorization code expires
  id: z.string(),
  oid4vpRequestObject: zOpenid4vpAuthorizationRequestPayload.optional(), // The request object associated with the authorization flow
  request_uri: z.string(), // The URI where the authorization request is stored
});

export const ParRequestV1_0 = zAuthorizationRequestV1_0.extend(
  WithCustomClaims.shape,
);

export const ParRequestV1_3 = zAuthorizationRequestV1_3.extend(
  WithCustomClaims.shape,
);

export const ParRequest = z.union([ParRequestV1_0, ParRequestV1_3]);

export function getPushedAuthorizationRequestSchema(config: IoWalletSdkConfig) {
  if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
    return ParRequestV1_0;
  }

  return ParRequestV1_3;
}

export type ParRequest = z.infer<typeof ParRequest>;
