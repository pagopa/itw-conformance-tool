import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { hashCallback } from '@itw-conformance-tool/crypto';
import { toResult } from '@itw-conformance-tool/utils';
import {
  HashAlgorithm,
  decodeJwt,
  verifyJwt,
  zJwk,
  type Jwk,
  type SignJwtCallback,
  type VerifyJwtCallback,
  type WalletAttestationOptionsV1_4
} from '@pagopa/io-wallet-oauth2';
import { CLOCK_SKEW_TOLERANCE_SECONDS, calculateJwkThumbprint, verifyJwtIatOrThrow } from '@pagopa/io-wallet-utils';
import { SignJWT, importJWK, jwtVerify, type JWK, type JWTPayload } from 'jose';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

const ATTESTATION_TTL_SECONDS = 3600;
const REQUEST_JWT_TYPE = 'wia-request+jwt';
const ATTESTATION_STATUS_LIST_INDEX = 0;
const WIA_REQUEST_ALLOWED_ALGORITHMS = ['ES256', 'ES384', 'ES512'] as const;
export const walletInstanceAttestationRequestSchema = z.object({
  assertion: z.string().min(1).describe('Signed Wallet Instance Attestation request JWT.')
});

export const walletInstanceAttestationResponseSchema = z.object({
  wallet_instance_attestation: z.string().describe('Provider-signed Wallet Instance Attestation JWT.')
});

export const walletInstanceAttestationErrorSchema = z.object({
  error: z.enum(['bad_request', 'integrity_check_error', 'invalid_request']),
  error_description: z.string().min(1)
});

const wiaRequestJwtHeaderSchema = z.strictObject({
  alg: z.enum(WIA_REQUEST_ALLOWED_ALGORITHMS),
  kid: z.string().min(1),
  typ: z.literal(REQUEST_JWT_TYPE)
});

const attestationRequiredStringClaims = [
  'hardware_key_tag',
  'hardware_signature',
  'integrity_assertion',
  'iss',
  'nonce',
  'platform',
  'wallet_solution_id',
  'wallet_solution_version'
] as const;

const attestationRequestPayloadSchema = z.strictObject({
  cnf: z.object({ jwk: zJwk }),
  exp: z.number().int(),
  hardware_key_tag: z.string().min(1),
  hardware_signature: z.string().min(1),
  iat: z.number().int(),
  integrity_assertion: z.string().min(1),
  iss: z.string().min(1),
  nonce: z.string().min(1),
  platform: z.string().min(1),
  wallet_solution_id: z.string().min(1),
  wallet_solution_version: z.string().min(1)
});

type AttestationRequestBody = z.infer<typeof walletInstanceAttestationRequestSchema>;

type AttestationRequestHeader = z.infer<typeof wiaRequestJwtHeaderSchema>;

type AttestationRequestPayload = z.infer<typeof attestationRequestPayloadSchema>;

type AttestationError = {
  description: string;
  error: 'bad_request' | 'integrity_check_error' | 'invalid_request';
  statusCode: 400 | 403;
};

function isAttestationError(value: unknown): value is AttestationError {
  return typeof value === 'object' && value !== null && 'statusCode' in value;
}
function invalidRequest(description: string): AttestationError {
  return { description, error: 'invalid_request', statusCode: 403 };
}

const verifyAssertionJwtCallback: VerifyJwtCallback = async (jwtSigner, jwt) => {
  if (jwtSigner.method !== 'jwk') return { verified: false };

  try {
    await jwtVerify(jwt.compact, await importJWK(jwtSigner.publicJwk as JWK, jwtSigner.alg), {
      algorithms: [jwtSigner.alg],
      clockTolerance: CLOCK_SKEW_TOLERANCE_SECONDS
    });
    return { signerJwk: jwtSigner.publicJwk, verified: true };
  } catch {
    return { verified: false };
  }
};

function createWalletProviderSignJwtCallback(signingPrivateJwk: JWK, signingPublicJwk: JWK): SignJwtCallback {
  return async (jwtSigner, jwt) => {
    const signingKey = await importJWK(signingPrivateJwk, jwtSigner.alg);
    const token = await new SignJWT(jwt.payload as JWTPayload)
      .setProtectedHeader({ ...jwt.header, alg: jwtSigner.alg })
      .sign(signingKey);

    return { jwt: token, signerJwk: signingPublicJwk as Jwk };
  };
}

async function calculateAssertionJwkThumbprint(jwk: Jwk): Promise<string> {
  return calculateJwkThumbprint({ hashAlgorithm: HashAlgorithm.Sha256, hashCallback, jwk });
}

function hasPrivateOrSymmetricKeyMaterial(jwk: Jwk): boolean {
  return 'd' in jwk || 'k' in jwk || 'p' in jwk || 'q' in jwk || 'dp' in jwk || 'dq' in jwk || 'qi' in jwk;
}

function validationErrorForPayload(error: z.ZodError<AttestationRequestPayload>): AttestationError {
  const invalidPaths = new Set(error.issues.map((issue) => issue.path.join('.')));

  if (invalidPaths.has('cnf') || invalidPaths.has('cnf.jwk')) {
    return { description: 'The assertion cnf.jwk claim is required.', error: 'bad_request', statusCode: 400 };
  }

  for (const claim of attestationRequiredStringClaims) {
    if (invalidPaths.has(claim)) {
      return { description: `The assertion ${claim} claim is required.`, error: 'bad_request', statusCode: 400 };
    }
  }

  if (invalidPaths.has('iat') || invalidPaths.has('exp')) {
    return { description: 'The assertion iat and exp claims are required.', error: 'bad_request', statusCode: 400 };
  }

  return { description: 'The assertion payload is invalid.', error: 'bad_request', statusCode: 400 };
}

function validatePayload(payload: unknown): AttestationRequestPayload | AttestationError {
  const parsedPayload = attestationRequestPayloadSchema.safeParse(payload);
  return parsedPayload.success ? parsedPayload.data : validationErrorForPayload(parsedPayload.error);
}

function validateHeader(header: unknown): AttestationRequestHeader | AttestationError {
  const parsedHeader = wiaRequestJwtHeaderSchema.safeParse(header);
  return parsedHeader.success
    ? parsedHeader.data
    : {
        description: 'The assertion must use a supported wia-request+jwt protected header.',
        error: 'bad_request',
        statusCode: 400
      };
}

function validateIssuedAt(payload: AttestationRequestPayload): AttestationError | undefined {
  try {
    verifyJwtIatOrThrow({ iat: payload.iat });
  } catch {
    return invalidRequest('The assertion iat claim is outside the allowed time window.');
  }
  return undefined;
}

async function verifyAssertionSignature(
  assertion: string,
  header: AttestationRequestHeader,
  payload: AttestationRequestPayload,
  expectedIssuer: string
): Promise<void> {
  await verifyJwt({
    allowedSkewInSeconds: CLOCK_SKEW_TOLERANCE_SECONDS,
    compact: assertion,
    expectedIssuer,
    header,
    payload,
    signer: { alg: header.alg, kid: header.kid, method: 'jwk', publicJwk: payload.cnf.jwk },
    verifyJwtCallback: verifyAssertionJwtCallback
  });
}

async function issueWalletInstanceAttestation(
  options: Pick<FastifyRequest['server'], 'config' | 'jwks' | 'walletProvider'>,
  payload: AttestationRequestPayload
): Promise<string> {
  const { private: signingPrivateJwk, public: signingPublicJwk } = options.jwks.sig;
  const expiresAt = new Date(Date.now() + ATTESTATION_TTL_SECONDS * 1000);

  return options.walletProvider.createItWalletAttestationJwt({
    callbacks: {
      hash: hashCallback,
      signJwt: createWalletProviderSignJwtCallback(signingPrivateJwk, signingPublicJwk)
    },
    dpopJwkPublic: payload.cnf.jwk,
    expiresAt,
    issuer: options.config.BASE_URL,
    signer: {
      alg: 'ES256',
      kid: signingPublicJwk.kid,
      method: 'x5c',
      x5c: options.config.WALLET_PROVIDER_X509_CHAIN
    },
    status: {
      status_list: {
        idx: ATTESTATION_STATUS_LIST_INDEX,
        uri: `${options.config.BASE_URL}/wallet-instance-attestation/status-list`
      }
    },
    walletLink: options.config.BASE_URL,
    walletName: options.config.WALLET_NAME
  } satisfies WalletAttestationOptionsV1_4);
}

function sendError(reply: FastifyReply, error: AttestationError): FastifyReply {
  return reply.code(error.statusCode).type('application/json').send({
    error: error.error,
    error_description: error.description
  });
}

export const issueWalletInstanceAttestationHandler = async (
  request: FastifyRequest<{ Body: AttestationRequestBody }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const { assertion } = request.body;

  const decodedAssertion = await toResult(decodeJwt({ jwt: assertion }));
  if (!decodedAssertion.ok) {
    return sendError(reply, {
      description: 'The assertion must be a compact JWT.',
      error: 'bad_request',
      statusCode: 400
    });
  }

  const header = validateHeader(decodedAssertion.value.header);
  if (isAttestationError(header)) return sendError(reply, header);

  const payload = validatePayload(decodedAssertion.value.payload);
  if (isAttestationError(payload)) return sendError(reply, payload);

  const issuedAtError = validateIssuedAt(payload);
  if (issuedAtError) return sendError(reply, issuedAtError);

  if (payload.iss !== request.server.config.BASE_URL) {
    return sendError(reply, invalidRequest('The assertion iss claim does not match the Wallet Provider identifier.'));
  }

  const jwkThumbprint = await toResult(calculateAssertionJwkThumbprint(payload.cnf.jwk));
  if (!jwkThumbprint.ok) {
    return sendError(reply, {
      description: 'The assertion cnf.jwk claim is invalid.',
      error: 'bad_request',
      statusCode: 400
    });
  }

  if (header.kid !== jwkThumbprint.value) {
    return sendError(reply, invalidRequest('The assertion kid does not match the cnf.jwk thumbprint.'));
  }

  try {
    await verifyAssertionSignature(assertion, header, payload, request.server.config.BASE_URL);
  } catch {
    return sendError(reply, invalidRequest('The assertion signature cannot be verified with cnf.jwk.'));
  }

  // The local conformance fixture exposes deterministic negative paths without impersonating a device-integrity service.
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

  const walletInstanceAttestation = await issueWalletInstanceAttestation(request.server, payload);

  await request.server.conformanceEventSink?.emit(
    createObservedEvent({
      name: 'wallet_attestation.requested',
      correlationId: request.conformance?.correlation?.correlationId ?? null,
      service: 'wallet-provider',
      requestId: request.id,
      diagnostic: {
        assertionAlg: header.alg,
        assertionKid: header.kid,
        assertionKidMatchesCnfJwkThumbprint: true,
        cnfJwkAsymmetric: payload.cnf.jwk.kty !== 'oct',
        cnfJwkPublicOnly: !hasPrivateOrSymmetricKeyMaterial(payload.cnf.jwk),
        cnfJwkThumbprint: jwkThumbprint.value,
        endpoint: '/wallet-instance-attestation',
        method: 'POST',
        outcome: 'success',
        proofVerifiedWithCnfJwk: true,
        statusCode: 200
      }
    })
  );

  return reply.code(200).type('application/json').send({ wallet_instance_attestation: walletInstanceAttestation });
};
