import { zAuthorizationRequest } from "@pagopa/io-wallet-oauth2";
import { z } from "zod";

export const ParRequest = zAuthorizationRequest.extend({
  code: z.string().optional(), // The authorization code returned by the authorization server
  code_consumed_at: z.number().optional(), // Unix timestamp (seconds) when the authorization code was consumed
  code_expires_at: z.number().optional(), // Unix timestamp (seconds) when the authorization code expires
  oid4vpRequestObject: z.any().optional(), // The request object associated with the authorization flow
  request_uri: z.string(), // The URI where the authorization request is stored
});

export type ParRequest = z.infer<typeof ParRequest>;
