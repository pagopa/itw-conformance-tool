import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';

import { DeferredCredentialAuthError, DeferredCredentialService, InvalidTransactionIdError } from '../domain/index.js';
import { makeOauthCallbacks } from '../plugins/index.js';

import type { HttpMethod } from '@pagopa/io-wallet-utils';
import type { FastifyPluginAsync } from 'fastify';

const firstHeaderValue = (value: string | string[] | undefined): string | undefined =>
  Array.isArray(value) ? value.at(0) : value;

const sha256Base64Url = (value: string): string => createHash('sha256').update(value, 'utf8').digest('base64url');

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function transactionIdFromBody(value: unknown): string | undefined {
  if (typeof value === 'string') {
    try {
      return transactionIdFromBody(JSON.parse(value) as unknown);
    } catch {
      return undefined;
    }
  }

  if (!isRecord(value)) return undefined;
  return typeof value.transaction_id === 'string' && value.transaction_id.length > 0 ? value.transaction_id : undefined;
}

function countResponseCredentials(value: unknown): number | undefined {
  if (!isRecord(value) || !Array.isArray(value.credentials)) {
    return undefined;
  }

  return value.credentials.length;
}

function hasNotificationId(value: unknown): boolean {
  return isRecord(value) && typeof value['notification_id'] === 'string';
}

const deferredRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/deferred',
    method: 'POST',
    schema: {
      tags: ['Credential'],
      body: {
        type: 'object',
        properties: {
          transaction_id: { type: 'string', minLength: 1 }
        },
        required: ['transaction_id'],
        additionalProperties: false
      }
    },
    handler: async (request, reply) => {
      const body = typeof request.body === 'string' ? request.body : JSON.stringify(request.body ?? {});
      const { baseURL, headers, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);
      const transactionId = transactionIdFromBody(request.body);

      reply.header('Cache-Control', 'no-store');

      try {
        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'issuer.deferred_credential.requested',
            correlationId: request.conformance?.correlation?.correlationId ?? null,
            service: 'credential-issuer',
            requestId: request.id,
            diagnostic: {
              endpoint: '/deferred',
              method: 'POST',
              contentType: firstHeaderValue(request.headers['content-type']),
              transactionIdSha256: transactionId ? sha256Base64Url(transactionId) : undefined
            }
          })
        );

        const service = new DeferredCredentialService(app.deferredCredentialRepository);
        const result = await service.retrieveDeferredCredential({
          body,
          callbacks: {
            hash: oauthCallbacks.hash,
            verifyJwt: oauthCallbacks.verifyJwt
          },
          config: sdkConfig,
          headers,
          method: request.method as HttpMethod,
          url: `${baseURL}${request.url}`
        });
        const responseBody = result.credentialResponse ?? result;

        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'issuer.deferred_credential.issued',
            correlationId: request.conformance?.correlation?.correlationId ?? null,
            service: 'credential-issuer',
            requestId: request.id,
            diagnostic: {
              endpoint: '/deferred',
              statusCode: 200,
              contentType: 'application/json',
              transactionIdSha256: transactionId ? sha256Base64Url(transactionId) : undefined,
              credentialCount: countResponseCredentials(responseBody),
              notificationIdPresent: hasNotificationId(responseBody)
            }
          })
        );

        return reply.code(200).send(responseBody);
      } catch (error) {
        if (error instanceof InvalidTransactionIdError) {
          return reply.code(400).send({ error: 'invalid_transaction_id', error_description: error.message });
        }

        if (error instanceof DeferredCredentialAuthError) {
          return reply.code(400).send({ error: 'invalid_or_missing_proof', error_description: error.message });
        }

        request.log.error({ err: error }, 'Deferred credential retrieval failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default deferredRoute;
