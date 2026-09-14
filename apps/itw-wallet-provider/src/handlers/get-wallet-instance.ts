import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import { sendWalletProviderError, walletProviderErrorSchema } from '../utils/errors.js';

import type { RegisteredWalletInstance } from '../plugins/wallet-instance-registry.js';
import type { FastifyReply, FastifyRequest } from 'fastify';

const BASE64URL_WITH_OPTIONAL_PADDING = /^[A-Za-z0-9_-]+={0,2}$/;

export const walletInstanceStatusParamsSchema = z.strictObject({
  walletInstanceId: z.string().min(1).describe('Wallet Instance identifier.')
});

/**
 * `WalletInstanceData` as consumed by `io-react-native-wallet`
 * (`WalletInstanceApi.getWalletInstanceStatus` / `getCurrentWalletInstanceStatus`).
 */
export const walletInstanceStatusResponseSchema = z.object({
  id: z.string().min(1).describe('Unique Wallet Instance identifier.'),
  is_revoked: z.boolean().describe('Whether the Wallet Instance has been revoked.'),
  revocation_reason: z
    .enum([
      'CERTIFICATE_REVOKED_BY_ISSUER',
      'NEW_WALLET_INSTANCE_CREATED',
      'REVOKED_BY_USER',
      'WALLET_INSTANCE_RENEWAL'
    ])
    .optional()
    .describe('Reason the Wallet Instance was revoked. Present only for revoked Wallet Instances.')
});

export const walletInstanceStatusErrorSchema = walletProviderErrorSchema([
  'bad_request',
  'forbidden',
  'not_found',
  'server_error',
  'temporarily_unavailable',
  'unauthorized',
  'validation_error'
]);

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
  return sendWalletProviderError(reply, statusCode, error, error_description);
}

function toWalletInstanceData(walletInstanceId: string, walletInstance: RegisteredWalletInstance) {
  const isRevoked = walletInstance.status === 'REVOKED';

  return {
    id: walletInstanceId,
    is_revoked: isRevoked,
    ...(isRevoked && walletInstance.revocationReason ? { revocation_reason: walletInstance.revocationReason } : {})
  };
}

async function emitStatusRetrievalEvent(
  request: FastifyRequest,
  endpoint: string,
  diagnostic: Record<string, unknown>
): Promise<void> {
  await request.server.conformanceEventSink?.emit(
    createObservedEvent({
      name: 'wallet_instance.status_retrieval.requested',
      correlationId: request.conformance?.correlation?.correlationId ?? null,
      service: 'wallet-provider',
      requestId: request.id,
      diagnostic: { endpoint, method: 'GET', ...diagnostic }
    })
  );
}

const STATUS_ENDPOINT = '/wallet-instances/:walletInstanceId/status';
const CURRENT_STATUS_ENDPOINT = '/wallet-instances/current/status';

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
    await emitStatusRetrievalEvent(request, STATUS_ENDPOINT, {
      error: error.error,
      outcome: 'error',
      statusCode: error.statusCode,
      walletInstanceId
    });
    return sendStatusError(reply, error);
  }

  const walletInstance = request.server.registeredWalletInstances.get(walletInstanceId);

  if (walletInstance === undefined) {
    const error = statusError(404, 'not_found', 'The Wallet Instance was not found.');
    await emitStatusRetrievalEvent(request, STATUS_ENDPOINT, {
      error: error.error,
      outcome: 'error',
      statusCode: error.statusCode,
      walletInstanceId
    });
    return sendStatusError(reply, error);
  }

  await emitStatusRetrievalEvent(request, STATUS_ENDPOINT, {
    outcome: 'success',
    statusCode: 200,
    walletInstanceId,
    walletInstanceStatus: walletInstance.status
  });

  return reply
    .code(200)
    .header('cache-control', 'no-store')
    .send(toWalletInstanceData(walletInstanceId, walletInstance));
};

/**
 * A deployed Wallet Provider resolves "the current Wallet Instance" from the
 * authenticated user. This fixture has no user session, so the endpoint answers
 * for a fixed placeholder Wallet Instance.
 */
const CURRENT_WALLET_INSTANCE_ID = 'current-wallet-instance';

export const getCurrentWalletInstanceStatusHandler = async (
  request: FastifyRequest,
  reply: FastifyReply
): Promise<FastifyReply> => {
  await emitStatusRetrievalEvent(request, CURRENT_STATUS_ENDPOINT, {
    outcome: 'success',
    statusCode: 200,
    walletInstanceId: CURRENT_WALLET_INSTANCE_ID,
    walletInstanceStatus: 'ACTIVE'
  });

  return reply
    .code(200)
    .header('cache-control', 'no-store')
    .send({ id: CURRENT_WALLET_INSTANCE_ID, is_revoked: false });
};
