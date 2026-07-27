import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

const BASE64URL_WITH_OPTIONAL_PADDING = /^[A-Za-z0-9_-]+={0,2}$/;

export const walletInstanceRevocationParamsSchema = z.strictObject({
  walletInstanceId: z.string().min(1).describe('Wallet Instance identifier.')
});

export const walletInstanceRevocationRequestSchema = z.strictObject({
  status: z.literal('REVOKED').describe('Requested Wallet Instance lifecycle status.')
});

export const walletInstanceRevocationErrorSchema = z.object({
  error: z.enum([
    'bad_request',
    'invalid_request',
    'not_found',
    'server_error',
    'temporarily_unavailable',
    'unauthorized',
    'validation_error'
  ]),
  error_description: z.string().min(1)
});

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
  return reply.code(statusCode).header('cache-control', 'no-store').send({ error, error_description });
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
      diagnostic: { endpoint: '/wallet-instances/:walletInstanceId', ...diagnostic }
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
    await emitRevocationEvent(request, { error: body.error, statusCode: body.statusCode, walletInstanceId });
    return sendRevocationError(reply, body);
  }

  if (!BASE64URL_WITH_OPTIONAL_PADDING.test(walletInstanceId)) {
    const error = revocationError(
      422,
      'validation_error',
      'The walletInstanceId path parameter must be base64url encoded.'
    );
    await emitRevocationEvent(request, { error: error.error, statusCode: error.statusCode, walletInstanceId });
    return sendRevocationError(reply, error);
  }

  const walletInstance = request.server.registeredWalletInstances.get(walletInstanceId);

  if (walletInstance === undefined) {
    const error = revocationError(404, 'not_found', 'The Wallet Instance was not found.');
    await emitRevocationEvent(request, { error: error.error, statusCode: error.statusCode, walletInstanceId });
    return sendRevocationError(reply, error);
  }

  walletInstance.status = body.status;

  await emitRevocationEvent(request, {
    statusCode: 204,
    walletInstanceId,
    walletInstanceStatus: walletInstance.status
  });

  return reply.code(204).send();
};
