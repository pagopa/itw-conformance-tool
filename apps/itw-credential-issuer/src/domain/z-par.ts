import { zAuthorizationRequestV1_0, zAuthorizationRequestV1_3 } from '@pagopa/io-wallet-oauth2';
import { zOpenid4vpAuthorizationRequestPayload } from '@pagopa/io-wallet-oid4vp';
import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { z } from 'zod';

const zPidAuthFlow = z.enum(['direct', 'l2plus', 'l3']);
const zMockLoa = z.enum(['substantial', 'high']);

const zMockIdentity = z.object({
  birthdate: z.string(),
  family_name: z.string(),
  given_name: z.string(),
  personal_administrative_number: z.string(),
  place_of_birth: z.object({
    country: z.string(),
    locality: z.string(),
    region: z.string()
  })
});

const zMrtdAuthSessionState = z.enum(['created', 'pending_mrtd_init', 'pending_mrtd_verify', 'verified', 'completed']);

const zMrtdAuthSession = z.object({
  auth_flow: z.literal('l2plus'),
  challenge: z.string().optional(),
  created_at: z.number(),
  expires_at: z.number(),
  identity: zMockIdentity,
  mrtd_auth_session: z.string(),
  mrtd_pop_jwt_nonce: z.string(),
  mrtd_pop_jwt_nonce_consumed_at: z.number().optional(),
  mrtd_pop_nonce: z.string().optional(),
  mrtd_pop_nonce_consumed_at: z.number().optional(),
  mrtd_val_pop_nonce: z.string().optional(),
  mrtd_val_pop_nonce_consumed_at: z.number().optional(),
  status: zMrtdAuthSessionState,
  wallet_public_key: z.record(z.string(), z.unknown()).optional()
});

const WithCustomClaims = z.object({
  code: z.string().optional(),
  code_consumed_at: z.number().optional(),
  code_expires_at: z.number().optional(),
  id: z.string(),
  mock_identity: zMockIdentity.optional(),
  mock_loa: zMockLoa.optional(),
  mrtd_auth_session: zMrtdAuthSession.optional(),
  oid4vpRequestObject: zOpenid4vpAuthorizationRequestPayload.optional(),
  pid_auth_flow: zPidAuthFlow.optional(),
  request_uri: z.string()
});

export const ParRequestV1_0 = zAuthorizationRequestV1_0.extend(WithCustomClaims.shape);
export const ParRequestV1_3 = zAuthorizationRequestV1_3.extend(WithCustomClaims.shape);
export const ParRequest = z.union([ParRequestV1_0, ParRequestV1_3]);

export type ParRequest = z.infer<typeof ParRequest>;
export type PidAuthFlow = z.infer<typeof zPidAuthFlow>;
export type MockLoa = z.infer<typeof zMockLoa>;
export type MockIdentity = z.infer<typeof zMockIdentity>;
export type MrtdAuthSessionState = z.infer<typeof zMrtdAuthSessionState>;
export type MrtdAuthSession = z.infer<typeof zMrtdAuthSession>;

export function getPushedAuthorizationRequestSchema(config: IoWalletSdkConfig) {
  if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
    return ParRequestV1_0;
  }
  return ParRequestV1_3;
}
