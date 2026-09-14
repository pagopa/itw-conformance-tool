import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import { sendWalletProviderError, walletProviderErrorSchema } from '../utils/errors.js';

import type { FastifyReply, FastifyRequest } from 'fastify';

const BASE64URL_WITH_OPTIONAL_PADDING = /^[A-Za-z0-9_-]+={0,2}$/;
const INTEGRITY_FAILURE_SENTINELS = new Set(['integrity_check_error', 'device_integrity_failed']);
const INVALID_REQUEST_SENTINELS = new Set(['invalid_request', 'invalid_key_attestation']);

export const walletInstanceRegistrationRequestSchema = z.strictObject({
  challenge: z.string().min(1).describe('Nonce obtained from the Wallet Provider nonce endpoint.'),
  hardware_key_tag: z.string().min(1).describe('Base64url-encoded Cryptographic Hardware Key tag.'),
  is_renewal: z.boolean().optional().describe('Whether the Wallet Instance replaces an existing one.'),
  key_attestation: z.string().min(1).describe('Device key attestation bound to the nonce and hardware key tag.')
});

export const walletInstanceRegistrationErrorSchema = walletProviderErrorSchema([
  'bad_request',
  'integrity_check_error',
  'invalid_request',
  'server_error',
  'temporarily_unavailable',
  'validation_error'
]);

type WalletInstanceRegistrationBody = z.infer<typeof walletInstanceRegistrationRequestSchema>;
type WalletInstanceRegistrationErrorCode = z.infer<typeof walletInstanceRegistrationErrorSchema>['error'];

type WalletInstanceRegistrationError = {
  error: WalletInstanceRegistrationErrorCode;
  error_description: string;
  statusCode: number;
};

function walletInstanceRegistrationError(
  statusCode: number,
  error: WalletInstanceRegistrationErrorCode,
  error_description: string
): WalletInstanceRegistrationError {
  return { error, error_description, statusCode };
}

function badRequest(description: string): WalletInstanceRegistrationError {
  return walletInstanceRegistrationError(400, 'bad_request', description);
}

function sendWalletInstanceRegistrationError(
  reply: FastifyReply,
  { error, error_description, statusCode }: WalletInstanceRegistrationError
): FastifyReply {
  return sendWalletProviderError(reply, statusCode, error, error_description);
}

function validateRequestBody(body: unknown): WalletInstanceRegistrationBody | WalletInstanceRegistrationError {
  const parseResult = walletInstanceRegistrationRequestSchema.safeParse(body);

  if (!parseResult.success) {
    const firstIssue = parseResult.error.issues[0];
    const description = firstIssue?.path.length
      ? `The request is missing or has an invalid ${firstIssue.path.join('.')} parameter.`
      : 'The request is malformed, missing required parameters, or includes invalid and unknown parameters.';

    return badRequest(description);
  }

  return parseResult.data;
}

function validateRegistrationSemantics(
  body: WalletInstanceRegistrationBody
): undefined | WalletInstanceRegistrationError {
  if (!BASE64URL_WITH_OPTIONAL_PADDING.test(body.hardware_key_tag)) {
    return walletInstanceRegistrationError(
      422,
      'validation_error',
      'The hardware_key_tag parameter must be base64url encoded.'
    );
  }

  if (INVALID_REQUEST_SENTINELS.has(body.key_attestation)) {
    return walletInstanceRegistrationError(
      403,
      'invalid_request',
      'The provided nonce is invalid, expired, or already used, or the Key Attestation signature is invalid.'
    );
  }

  if (INTEGRITY_FAILURE_SENTINELS.has(body.key_attestation)) {
    return walletInstanceRegistrationError(
      403,
      'integrity_check_error',
      "The device does not meet the Wallet Provider's minimum security requirements."
    );
  }

  return undefined;
}

export const registerWalletInstanceHandler = async (
  request: FastifyRequest<{ Body: unknown }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const body = validateRequestBody(request.body);

  if ('statusCode' in body) {
    return sendWalletInstanceRegistrationError(reply, body);
  }

  const semanticError = validateRegistrationSemantics(body);

  if (semanticError !== undefined) {
    return sendWalletInstanceRegistrationError(reply, semanticError);
  }

  if (!request.server.walletNonces.consume(body.challenge)) {
    return sendWalletInstanceRegistrationError(
      reply,
      walletInstanceRegistrationError(
        403,
        'invalid_request',
        'The provided nonce is invalid, expired, or already used.'
      )
    );
  }

  const isRenewal = body.is_renewal ?? false;

  request.server.registeredWalletInstances.set(body.hardware_key_tag, {
    isRenewal,
    keyAttestation: body.key_attestation,
    nonce: body.challenge,
    registeredAt: new Date().toISOString(),
    status: 'ACTIVE'
  });

  await request.server.conformanceEventSink?.emit(
    createObservedEvent({
      name: 'wallet_instance.registration.requested',
      correlationId: request.conformance?.correlation?.correlationId ?? null,
      service: 'wallet-provider',
      requestId: request.id,
      diagnostic: {
        endpoint: '/wallet-instances',
        isRenewal,
        method: 'POST',
        outcome: 'success',
        statusCode: 204
      }
    })
  );

  return reply.code(204).send();
};
