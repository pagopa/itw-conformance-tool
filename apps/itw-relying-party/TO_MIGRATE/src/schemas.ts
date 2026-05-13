import * as z from 'zod';

const FlowType = z.enum(['same-device', 'cross-device']);

export type FlowType = z.infer<typeof FlowType>;

export const AuthorizationRequest = z
  .object({
    dcqlQuery: z.object({
      credential_sets: z
        .array(
          z.object({
            options: z.array(z.array(z.string())),
            purpose: z.union([z.string(), z.number(), z.record(z.any())]).optional(),
            required: z.boolean().optional()
          })
        )
        .optional(),
      credentials: z.array(
        z.object({
          claim_sets: z.array(z.array(z.string())).optional(),
          claims: z
            .array(
              z.object({
                id: z.string().optional(),
                path: z.array(z.string()),
                values: z.array(z.union([z.string(), z.number(), z.boolean()])).optional()
              })
            )
            .optional(),
          format: z.enum(['vc+sd-jwt', 'dc+sd-jwt']),
          id: z.string(),
          meta: z.object({ vct_values: z.array(z.string()) }).optional()
        })
      )
    }),
    flow_type: FlowType,
    wallet_auth_base_uri: z.string().trim().min(1).url('Invalid URL').default('https://continua.io.pagopa.it/itw/auth')
  })
  .transform(({ dcqlQuery, flow_type, wallet_auth_base_uri }) => ({
    dcqlQuery,
    flowType: flow_type,
    walletAuthBaseUri: wallet_auth_base_uri
  }));

export type AuthorizationRequest = z.infer<typeof AuthorizationRequest>;

export type Disclosure = [string, string, unknown];

export type ClaimsObject = Record<string, Record<string, Record<string, unknown>>>;

export const IssuerSignedJwtPayload = z.object({
  _sd: z.array(z.string()),
  _sd_alg: z.string(),
  cnf: z.object({
    jwk: z.object({
      crv: z.literal('P-256'),
      kid: z.string(),
      kty: z.literal('EC'),
      x: z.string(),
      y: z.string()
    })
  }),
  exp: z.number(),
  iss: z.string(),
  status: z.object({
    status_assertion: z.object({
      credential_hash_alg: z.string()
    })
  }),
  sub: z.string(),
  vct: z.string()
});

export type IssuerSignedJwtPayload = z.infer<typeof IssuerSignedJwtPayload>;

export const IssuerEC = z.object({
  metadata: z.object({
    openid_credential_issuer: z.object({
      jwks: z.object({
        keys: z.array(
          z.object({
            alg: z.string().optional(),
            crv: z.string(),
            kid: z.string(),
            kty: z.string(),
            use: z.string().optional(),
            x: z.string(),
            y: z.string()
          })
        )
      })
    })
  })
});

export const WalletProviderEC = z.object({
  metadata: z.object({
    wallet_provider: z.object({
      jwks: z.object({
        keys: z.array(
          z.object({
            crv: z.string(),
            kid: z.string(),
            kty: z.string(),
            x: z.string(),
            y: z.string()
          })
        )
      })
    })
  })
});

// asymmetric algorithms in https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
export const CryptographicAlgorithms = z.enum([
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512',
  'PS256',
  'PS384',
  'PS512'
]);

export const KbJwtPayload = z.object({
  aud: z.string(),
  iat: z.number(),
  nonce: z.string(),
  sd_hash: z.string()
});

export type KbJwtPayload = z.infer<typeof KbJwtPayload>;

export type DcqlPresentation = Record<
  string,
  {
    claims: Record<string, unknown>;
    credential_format: 'dc+sd-jwt' | 'vc+sd-jwt';
    vct: string;
  }
>;

// change name
const errorSchema = z.enum([
  'invalid_request_object',
  'invalid_request_uri',
  'vp_formats_not_supported',
  'invalid_request',
  'access_denied',
  'invalid_client'
]);

// schema Zod to support both sucess and error
export const responseBody = z
  .object({
    error: errorSchema.optional(),
    error_description: z.string().optional(),
    response: z.string().optional(),
    state: z.string().optional()
  })
  .refine((data) => data.response || (data.error && data.error_description && data.state), {
    message: "Either 'response' or 'error, error_description, state' must be present",
    path: ['response_or_error']
  });

export type ResponseBody = z.infer<typeof responseBody>;
