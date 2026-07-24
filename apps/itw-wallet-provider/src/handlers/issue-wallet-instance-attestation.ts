import { convertPemToBase64Der, createSelfSignedCertificateFromJwk } from '@itw-conformance-tool/crypto';
import {
  SignJWT,
  calculateJwkThumbprint,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload
} from 'jose';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

const ATTESTATION_TTL_SECONDS = 3600;
const REQUEST_JWT_TYPE = 'wia-request+jwt';
const RESPONSE_JWT_TYPE = 'oauth-client-attestation+jwt';
const signingCertificates = new Map<string, Promise<string>>();
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

type AttestationRequestBody = z.infer<typeof walletInstanceAttestationRequestSchema>;

type AttestationRequestPayload = JWTPayload & {
  cnf: { jwk: JWK };
  hardware_key_tag: string;
  hardware_signature: string;
  integrity_assertion: string;
  nonce: string;
  platform: string;
  wallet_solution_id: string;
  wallet_solution_version: string;
};

type AttestationError = {
  description: string;
  error: 'bad_request' | 'integrity_check_error' | 'invalid_request';
  statusCode: 400 | 403;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isAttestationError(value: AttestationRequestPayload | AttestationError): value is AttestationError {
  return 'statusCode' in value;
}

function signingCertificateCacheKey(jwk: JWK): string {
  return JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
}

function getSigningCertificate(jwk: JWK): Promise<string> {
  const cacheKey = signingCertificateCacheKey(jwk);
  const cachedCertificate = signingCertificates.get(cacheKey);
  if (cachedCertificate) return cachedCertificate;

  const certificate = createSelfSignedCertificateFromJwk(jwk);
  signingCertificates.set(cacheKey, certificate);
  return certificate;
}

function invalidRequest(description: string): AttestationError {
  return { description, error: 'invalid_request', statusCode: 403 };
}

function validatePayload(payload: JWTPayload): AttestationRequestPayload | AttestationError {
  if (!isRecord(payload.cnf) || !isRecord(payload.cnf.jwk)) {
    return { description: 'The assertion cnf.jwk claim is required.', error: 'bad_request', statusCode: 400 };
  }

  const requiredStringClaims = [
    'hardware_key_tag',
    'hardware_signature',
    'integrity_assertion',
    'nonce',
    'platform',
    'wallet_solution_id',
    'wallet_solution_version'
  ] as const;

  for (const claim of requiredStringClaims) {
    if (!isNonEmptyString(payload[claim])) {
      return { description: `The assertion ${claim} claim is required.`, error: 'bad_request', statusCode: 400 };
    }
  }

  if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number') {
    return { description: 'The assertion iat and exp claims are required.', error: 'bad_request', statusCode: 400 };
  }

  return payload as AttestationRequestPayload;
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

  let header: { alg?: string; kid?: string; typ?: string };
  let decodedPayload: JWTPayload;
  try {
    header = decodeProtectedHeader(assertion);
    decodedPayload = decodeJwt(assertion);
  } catch {
    return sendError(reply, {
      description: 'The assertion must be a compact JWT.',
      error: 'bad_request',
      statusCode: 400
    });
  }

  if (header.alg !== 'ES256' || header.typ !== REQUEST_JWT_TYPE || !isNonEmptyString(header.kid)) {
    return sendError(reply, {
      description: 'The assertion must use an ES256 wia-request+jwt protected header.',
      error: 'bad_request',
      statusCode: 400
    });
  }

  const payload = validatePayload(decodedPayload);
  if (isAttestationError(payload)) return sendError(reply, payload);

  let jwkThumbprint: string;
  try {
    jwkThumbprint = await calculateJwkThumbprint(payload.cnf.jwk);
  } catch {
    return sendError(reply, {
      description: 'The assertion cnf.jwk claim is invalid.',
      error: 'bad_request',
      statusCode: 400
    });
  }

  if (header.kid !== jwkThumbprint) {
    return sendError(reply, invalidRequest('The assertion kid does not match the cnf.jwk thumbprint.'));
  }

  try {
    await jwtVerify(assertion, await importJWK(payload.cnf.jwk, 'ES256'), { algorithms: ['ES256'] });
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

  const issuedAt = Math.floor(Date.now() / 1000);
  const { signingPrivateJwk, signingPublicJwk } = request.server.walletProviderKeys;
  const signingKey = await importJWK(signingPrivateJwk, 'ES256');
  const signingCertificate = await getSigningCertificate(signingPrivateJwk);

  const walletInstanceAttestation = await new SignJWT({
    cnf: { jwk: payload.cnf.jwk },
    wallet_link: request.server.config.baseUrl,
    wallet_name: request.server.config.walletName
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid: signingPublicJwk.kid,
      typ: RESPONSE_JWT_TYPE,
      x5c: [convertPemToBase64Der(signingCertificate)]
    })
    .setIssuedAt(issuedAt)
    .setIssuer(request.server.config.baseUrl)
    .setSubject(jwkThumbprint)
    .setExpirationTime(issuedAt + ATTESTATION_TTL_SECONDS)
    .sign(signingKey);

  return reply.code(200).type('application/json').send({ wallet_instance_attestation: walletInstanceAttestation });
};
