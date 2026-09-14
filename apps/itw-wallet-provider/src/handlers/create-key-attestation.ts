import { toResult } from '@itw-conformance-tool/utils';
import { decodeJwt, zJwk, type Jwk, type SignJwtCallback } from '@pagopa/io-wallet-oauth2';
import { type KeyAttestationOptions } from '@pagopa/io-wallet-oid4vci';
import { CLOCK_SKEW_TOLERANCE_SECONDS, verifyJwtIatOrThrow } from '@pagopa/io-wallet-utils';
import { SignJWT, importJWK, jwtVerify, type JWK, type JWTPayload } from 'jose';
import z from 'zod';

import { sendWalletProviderError, walletProviderErrorSchema } from '../utils/errors.js';

import type { FastifyReply, FastifyRequest } from 'fastify';

const KEY_ATTESTATION_TTL_SECONDS = 3600;
const REQUEST_JWT_TYPE = 'wua-request+jwt';
const ATTESTED_KEY_REQUEST_JWT_TYPE = 'key-attestation-request+jwt';
const KEY_ATTESTATION_STATUS_LIST_INDEX = 0;
const KEY_ATTESTATION_ALLOWED_ALGORITHMS = ['ES256', 'ES384', 'ES512'] as const;

/**
 * The Key Attestation request is the bare compact JWT posted with
 * `Content-Type: text/plain` by `io-react-native-wallet`
 * (`src/key-attestation/v1.4.6/issuing.ts`).
 */
export const keyAttestationRequestSchema = z.union([
  z.string().min(1).describe('Signed Key Attestation request JWT.'),
  z.object({ assertion: z.string().min(1).describe('Signed Key Attestation request JWT.') })
]);

export const keyAttestationResponseSchema = z.object({
  key_attestation: z.string().describe('Provider-signed Key Attestation JWT.')
});

export const keyAttestationErrorSchema = walletProviderErrorSchema([
  'bad_request',
  'integrity_check_error',
  'invalid_request'
]);

const keyAttestationRequestHeaderSchema = z.strictObject({
  alg: z.enum(KEY_ATTESTATION_ALLOWED_ALGORITHMS),
  kid: z.string().min(1),
  typ: z.literal(REQUEST_JWT_TYPE)
});

const attestedKeyRequestHeaderSchema = z.object({
  alg: z.enum(KEY_ATTESTATION_ALLOWED_ALGORITHMS),
  typ: z.literal(ATTESTED_KEY_REQUEST_JWT_TYPE)
});

const keyAttestationRequestPayloadSchema = z.strictObject({
  cnf: z.object({ jwk: zJwk }),
  exp: z.number().int(),
  hardware_key_tag: z.string().min(1),
  hardware_signature: z.string().min(1),
  iat: z.number().int(),
  integrity_assertion: z.string().min(1),
  iss: z.string().min(1),
  keys_to_attest: z.array(z.string().min(1)).min(1),
  nonce: z.string().min(1),
  platform: z.string().min(1),
  wallet_solution_id: z.string().min(1),
  wallet_solution_version: z.string().min(1)
});

type KeyAttestationRequestBody = z.infer<typeof keyAttestationRequestSchema>;
type KeyAttestationRequestPayload = z.infer<typeof keyAttestationRequestPayloadSchema>;

type KeyAttestationError = {
  description: string;
  error: 'bad_request' | 'integrity_check_error' | 'invalid_request';
  statusCode: 400 | 403;
};

function badRequest(description: string): KeyAttestationError {
  return { description, error: 'bad_request', statusCode: 400 };
}

function invalidRequest(description: string): KeyAttestationError {
  return { description, error: 'invalid_request', statusCode: 403 };
}

function sendError(reply: FastifyReply, error: KeyAttestationError): FastifyReply {
  return sendWalletProviderError(reply, error.statusCode, error.error, error.description);
}

function extractRequestJwt(body: unknown): string | undefined {
  if (typeof body === 'string') {
    return body.trim().length === 0 ? undefined : body.trim();
  }

  if (typeof body === 'object' && body !== null && 'assertion' in body) {
    const { assertion } = body as { assertion: unknown };
    return typeof assertion === 'string' && assertion.length > 0 ? assertion : undefined;
  }

  return undefined;
}

function createWalletProviderSignJwtCallback(signingPrivateJwk: JWK, signingPublicJwk: JWK): SignJwtCallback {
  return async (jwtSigner, jwt) => {
    const signingKey = await importJWK(signingPrivateJwk, jwtSigner.alg);
    const token = await new SignJWT(jwt.payload as JWTPayload)
      .setProtectedHeader({ ...jwt.header, alg: jwtSigner.alg })
      .sign(signingKey);

    return { jwt: token, signerJwk: signingPublicJwk as Jwk };
  };
}

/**
 * Each entry of `keys_to_attest` is a `key-attestation-request+jwt` that carries the
 * public key to attest in `cnf.jwk`, self-signed with that same key.
 */
async function collectAttestedKeys(
  keysToAttest: string[]
): Promise<{ error: KeyAttestationError } | { keys: [Jwk, ...Jwk[]] }> {
  const attestedKeys: Jwk[] = [];

  for (const keyRequestJwt of keysToAttest) {
    const decoded = await toResult(decodeJwt({ jwt: keyRequestJwt }));
    if (!decoded.ok) {
      return { error: badRequest('Each keys_to_attest entry must be a compact JWT.') };
    }

    const header = attestedKeyRequestHeaderSchema.safeParse(decoded.value.header);
    if (!header.success) {
      return {
        error: badRequest(`Each keys_to_attest entry must use the ${ATTESTED_KEY_REQUEST_JWT_TYPE} type.`)
      };
    }

    const payload = z.object({ cnf: z.object({ jwk: zJwk }) }).safeParse(decoded.value.payload);
    if (!payload.success) {
      return { error: badRequest('Each keys_to_attest entry must carry a cnf.jwk claim.') };
    }

    const attestedKey = payload.data.cnf.jwk;

    try {
      // `alg` is taken from the entry's own protected header: the exported public JWKs
      // the wallet sends carry no `alg` member, and jose requires one to import them.
      await jwtVerify(keyRequestJwt, await importJWK(attestedKey as JWK, header.data.alg), {
        algorithms: [header.data.alg],
        clockTolerance: CLOCK_SKEW_TOLERANCE_SECONDS
      });
    } catch {
      return { error: invalidRequest('Each keys_to_attest entry must be signed by the key it attests.') };
    }

    attestedKeys.push(attestedKey);
  }

  const [first, ...rest] = attestedKeys;
  if (first === undefined) {
    return { error: badRequest('The keys_to_attest claim must list at least one key.') };
  }

  return { keys: [first, ...rest] };
}

async function issueKeyAttestation(
  server: Pick<FastifyRequest['server'], 'config' | 'jwks' | 'walletProvider'>,
  attestedKeys: [Jwk, ...Jwk[]]
): Promise<string> {
  const { private: signingPrivateJwk, public: signingPublicJwk } = server.jwks.sig;

  return server.walletProvider.createItKeyAttestationJwt({
    attestedKeys,
    callbacks: { signJwt: createWalletProviderSignJwtCallback(signingPrivateJwk, signingPublicJwk) },
    expiresAt: new Date(Date.now() + KEY_ATTESTATION_TTL_SECONDS * 1000),
    issuer: server.config.BASE_URL,
    // This fixture has no real WSCD behind it, so it reports the levels a
    // hardware-backed keystore would claim.
    keyStorage: ['iso_18045_moderate'],
    signer: {
      alg: 'ES256',
      kid: signingPublicJwk.kid,
      method: 'x5c',
      x5c: server.config.WALLET_PROVIDER_X509_CHAIN
    },
    status: {
      status_list: {
        idx: KEY_ATTESTATION_STATUS_LIST_INDEX,
        uri: `${server.config.BASE_URL}/key-attestations/status-list`
      }
    },
    userAuthentication: ['iso_18045_moderate']
  } satisfies KeyAttestationOptions);
}

export const createKeyAttestationHandler = async (
  request: FastifyRequest<{ Body: KeyAttestationRequestBody }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const requestJwt = extractRequestJwt(request.body);

  if (requestJwt === undefined) {
    return sendError(reply, badRequest('The request body must carry the Key Attestation request JWT.'));
  }

  const decoded = await toResult(decodeJwt({ jwt: requestJwt }));
  if (!decoded.ok) {
    return sendError(reply, badRequest('The Key Attestation request must be a compact JWT.'));
  }

  const header = keyAttestationRequestHeaderSchema.safeParse(decoded.value.header);
  if (!header.success) {
    return sendError(reply, badRequest(`The request must use a supported ${REQUEST_JWT_TYPE} protected header.`));
  }

  const parsedPayload = keyAttestationRequestPayloadSchema.safeParse(decoded.value.payload);
  if (!parsedPayload.success) {
    const firstIssue = parsedPayload.error.issues[0];
    const claim = firstIssue?.path.join('.');
    return sendError(
      reply,
      badRequest(claim ? `The request ${claim} claim is required.` : 'The request payload is invalid.')
    );
  }

  const payload: KeyAttestationRequestPayload = parsedPayload.data;

  try {
    verifyJwtIatOrThrow({ iat: payload.iat });
  } catch {
    return sendError(reply, invalidRequest('The request iat claim is outside the allowed time window.'));
  }

  if (payload.iss !== payload.hardware_key_tag) {
    return sendError(reply, invalidRequest('The request iss claim must match the hardware_key_tag claim.'));
  }

  try {
    await jwtVerify(requestJwt, await importJWK(payload.cnf.jwk as JWK, header.data.alg), {
      algorithms: [header.data.alg],
      clockTolerance: CLOCK_SKEW_TOLERANCE_SECONDS
    });
  } catch {
    return sendError(reply, invalidRequest('The request signature cannot be verified with cnf.jwk.'));
  }

  // Deterministic negative paths, matching the Wallet Instance Attestation fixture.
  if (payload.integrity_assertion === 'invalid') {
    return sendError(reply, {
      description: 'The device does not meet the Wallet Provider security requirements.',
      error: 'integrity_check_error',
      statusCode: 403
    });
  }

  if (payload.hardware_signature === 'invalid' || payload.nonce === 'invalid') {
    return sendError(reply, invalidRequest('The Wallet Instance proof of possession or nonce is invalid.'));
  }

  if (!request.server.walletNonces.consume(payload.nonce)) {
    return sendError(reply, invalidRequest('The provided nonce is invalid, expired, or already used.'));
  }

  const attestedKeys = await collectAttestedKeys(payload.keys_to_attest);
  if ('error' in attestedKeys) {
    return sendError(reply, attestedKeys.error);
  }

  const keyAttestation = await issueKeyAttestation(request.server, attestedKeys.keys);

  return reply.code(200).type('application/json').send({ key_attestation: keyAttestation });
};
