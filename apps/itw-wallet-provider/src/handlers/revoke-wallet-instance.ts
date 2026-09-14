import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import { sendWalletProviderError, walletProviderErrorSchema } from '../utils/errors.js';

import type { FastifyReply, FastifyRequest } from 'fastify';

const BASE64URL_WITH_OPTIONAL_PADDING = /^[A-Za-z0-9_-]+={0,2}$/;
const REVOCATION_ENDPOINT = '/wallet-instances/:walletInstanceId/status';

export const walletInstanceRevocationParamsSchema = z.strictObject({
  walletInstanceId: z.string().min(1).describe('Wallet Instance identifier.')
});

export const walletInstanceRevocationRequestSchema = z.strictObject({
  status: z.literal('REVOKED').describe('Requested Wallet Instance lifecycle status.')
});

export const walletInstanceRevocationErrorSchema = walletProviderErrorSchema([
  'bad_request',
  'invalid_request',
  'not_found',
  'server_error',
  'temporarily_unavailable',
  'unauthorized',
  'validation_error'
]);

type WalletInstanceRevocationParams = z.infer<typeof walletInstanceRevocationParamsSchema>;
type WalletInstanceRevocationBody = z.infer<typeof walletInstanceRevocationRequestSchema>;
type WalletInstanceRevocationErrorCode = z.infer<typeof walletInstanceRevocationErrorSchema>['error'];

type WalletInstanceRevocationError = {
  error: WalletInstanceRevocationErrorCode;
  error_description: string;
  statusCode: 400 | 401 | 403 | 404 | 422;
};

function revocationError(
  statusCode: WalletInstanceRevocationError['statusCode'],
  error: WalletInstanceRevocationErrorCode,
  error_description: string
): WalletInstanceRevocationError {
  return { error, error_description, statusCode };
}

function sendRevocationError(
  reply: FastifyReply,
  { error, error_description, statusCode }: WalletInstanceRevocationError
): FastifyReply {
  return sendWalletProviderError(reply, statusCode, error, error_description);
}

function validateRevocationBody(body: unknown): WalletInstanceRevocationBody | WalletInstanceRevocationError {
  const parseResult = walletInstanceRevocationRequestSchema.safeParse(body);

  if (!parseResult.success) {
    const firstIssue = parseResult.error.issues[0];
    const description = firstIssue?.path.length
      ? `The request is missing or has an invalid ${firstIssue.path.join('.')} parameter.`
      : 'The request is malformed, missing required parameters, or includes invalid and unknown parameters.';

    return revocationError(400, 'bad_request', description);
  }

  return parseResult.data;
}

async function emitRevocationEvent(
  request: FastifyRequest<{ Body: unknown; Params: WalletInstanceRevocationParams }>,
  diagnostic: Record<string, unknown>
): Promise<void> {
  await request.server.conformanceEventSink?.emit(
    createObservedEvent({
      name: 'wallet_instance.revocation.requested',
      correlationId: request.conformance?.correlation?.correlationId ?? null,
      service: 'wallet-provider',
      requestId: request.id,
      diagnostic: { endpoint: REVOCATION_ENDPOINT, method: 'PUT', ...diagnostic }
    })
  );
}

export const revokeWalletInstanceHandler = async (
  request: FastifyRequest<{ Body: unknown; Params: WalletInstanceRevocationParams }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const { walletInstanceId } = request.params;

  const body = validateRevocationBody(request.body);

  if ('statusCode' in body) {
    await emitRevocationEvent(request, {
      error: body.error,
      outcome: 'error',
      statusCode: body.statusCode,
      walletInstanceId
    });
    return sendRevocationError(reply, body);
  }

  if (!BASE64URL_WITH_OPTIONAL_PADDING.test(walletInstanceId)) {
    const error = revocationError(
      422,
      'validation_error',
      'The walletInstanceId path parameter must be base64url encoded.'
    );
    await emitRevocationEvent(request, {
      error: error.error,
      outcome: 'error',
      statusCode: error.statusCode,
      walletInstanceId
    });
    return sendRevocationError(reply, error);
  }

  const walletInstance = request.server.registeredWalletInstances.get(walletInstanceId);

  if (walletInstance === undefined) {
    const error = revocationError(404, 'not_found', 'The Wallet Instance was not found.');
    await emitRevocationEvent(request, {
      error: error.error,
      outcome: 'error',
      statusCode: error.statusCode,
      walletInstanceId
    });
    return sendRevocationError(reply, error);
  }

  // Revoking an already revoked Wallet Instance succeeds and preserves the original reason.
  if (walletInstance.status !== 'REVOKED') {
    walletInstance.status = body.status;
    walletInstance.revocationReason = 'REVOKED_BY_USER';
  }

  await emitRevocationEvent(request, {
    outcome: 'success',
    statusCode: 204,
    walletInstanceId,
    walletInstanceRevocationReason: walletInstance.revocationReason,
    walletInstanceStatus: walletInstance.status
  });

  return reply.code(204).send();
};
