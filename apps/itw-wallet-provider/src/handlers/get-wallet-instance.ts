import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

const BASE64URL_WITH_OPTIONAL_PADDING = /^[A-Za-z0-9_-]+={0,2}$/;

export const walletInstanceStatusParamsSchema = z.strictObject({
  walletInstanceId: z.string().min(1).describe('Wallet Instance identifier.')
});

export const walletInstanceStatusResponseSchema = z.strictObject({
  wallet_instance_id: z.string().min(1).describe('Unique Wallet Instance identifier.'),
  status: z.enum(['ACTIVE', 'REVOKED']).describe('Current Wallet Instance lifecycle status.'),
  issuance_date: z.string().min(1).describe('ISO 8601 date-time when the Wallet Instance was registered.')
});

export const walletInstanceStatusErrorSchema = z.object({
  error: z.enum([
    'bad_request',
    'forbidden',
    'not_found',
    'server_error',
    'temporarily_unavailable',
    'unauthorized',
    'validation_error'
  ]),
  error_description: z.string().min(1)
});

type WalletInstanceStatusParams = z.infer<typeof walletInstanceStatusParamsSchema>;
type WalletInstanceStatusErrorCode = z.infer<typeof walletInstanceStatusErrorSchema>['error'];

type WalletInstanceStatusError = {
  error: WalletInstanceStatusErrorCode;
  error_description: string;
  statusCode: 401 | 403 | 404 | 422;
};

function statusError(
  statusCode: WalletInstanceStatusError['statusCode'],
  error: WalletInstanceStatusErrorCode,
  error_description: string
): WalletInstanceStatusError {
  return { error, error_description, statusCode };
}

function sendStatusError(reply: FastifyReply, { error, error_description, statusCode }: WalletInstanceStatusError) {
  return reply.code(statusCode).header('cache-control', 'no-store').send({ error, error_description });
}

async function emitStatusRetrievalEvent(
  request: FastifyRequest<{ Params: WalletInstanceStatusParams }>,
  diagnostic: Record<string, unknown>
): Promise<void> {
  await request.server.conformanceEventSink?.emit(
    createObservedEvent({
      name: 'wallet_instance.status_retrieval.requested',
      correlationId: request.conformance?.correlation?.correlationId ?? null,
      service: 'wallet-provider',
      requestId: request.id,
      diagnostic: { endpoint: '/wallet-instances/:walletInstanceId', ...diagnostic }
    })
  );
}

export const getWalletInstanceStatusHandler = async (
  request: FastifyRequest<{ Params: WalletInstanceStatusParams }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const { walletInstanceId } = request.params;

  if (!BASE64URL_WITH_OPTIONAL_PADDING.test(walletInstanceId)) {
    const error = statusError(
      422,
      'validation_error',
      'The walletInstanceId path parameter must be base64url encoded.'
    );
    await emitStatusRetrievalEvent(request, { error: error.error, statusCode: error.statusCode, walletInstanceId });
    return sendStatusError(reply, error);
  }

  const walletInstance = request.server.registeredWalletInstances.get(walletInstanceId);

  if (walletInstance === undefined) {
    const error = statusError(404, 'not_found', 'The Wallet Instance was not found.');
    await emitStatusRetrievalEvent(request, { error: error.error, statusCode: error.statusCode, walletInstanceId });
    return sendStatusError(reply, error);
  }

  await emitStatusRetrievalEvent(request, {
    statusCode: 200,
    walletInstanceId,
    walletInstanceStatus: walletInstance.status
  });

  return reply.code(200).header('cache-control', 'no-store').send({
    wallet_instance_id: walletInstanceId,
    status: walletInstance.status,
    issuance_date: walletInstance.registeredAt
  });
};
