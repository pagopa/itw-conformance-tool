import type { ICodeJwtParRepository, ITokenParRepository, JwksRepository } from '@itw-conformance-tool/issuer';
import type { CallbackContext } from '@pagopa/io-wallet-oauth2';
import type { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';
import type { FastifyInstance, FastifyRequest } from 'fastify';

export function makeJwksRepository(app: FastifyInstance): JwksRepository;

export function makeOauthCallbacks(
  app: FastifyInstance,
  request: FastifyRequest
): {
  baseURL: string;
  headers: Headers;
  jwksRepository: JwksRepository;
  oauthCallbacks: Pick<CallbackContext, 'encryptJwe' | 'fetch' | 'generateRandom' | 'hash' | 'signJwt' | 'verifyJwt'>;
  sdkConfig: IoWalletSdkConfig;
};

export function makeTokenParRepository(app: FastifyInstance): ITokenParRepository;

export function makeCodeJwtParRepository(app: FastifyInstance): ICodeJwtParRepository;
