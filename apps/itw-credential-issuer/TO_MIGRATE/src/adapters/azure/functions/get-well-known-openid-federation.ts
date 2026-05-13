import type { HttpHandler } from '@azure/functions';

import { getFederationMetadata } from '@/domain/openid-federation';

/**
 * Azure Function to handle the OpenID Federation metadata endpoint
 * at `.well-known/openid-federation`
 */
export const GetWellKnownOpenidFederationHandler: HttpHandler = async (_request, context) => {
  const federationMetadata = await getFederationMetadata({
    baseURL: context.app.config.baseURL,
    config: context.app.sdkConfig,
    jwksRepository: context.app.repository.jwks
  });

  return {
    body: federationMetadata,
    headers: {
      'Content-Type': 'application/entity-statement+jwt'
    },
    status: 200
  };
};
