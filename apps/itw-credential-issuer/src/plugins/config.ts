import { loadConfig } from '@itw-conformance-tool/config';
import { trimTrailingSlashes } from '@itw-conformance-tool/utils';
import fp from 'fastify-plugin';

import {
  buildCredentialOffer,
  createCredentialOfferUri,
  validateCredentialIdentifiers
} from '../domain/credential-offer.js';
import { SUPPORTED_CREDENTIAL_CONFIGURATION_IDS } from '../domain/openid-federation/index.js';

import type { IssuerAuthFlow } from '@itw-conformance-tool/config';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      AUTH_FLOW: IssuerAuthFlow;
      BATCH_ISSUANCE_BY_DEFERRED: boolean;
      TRUST_ANCHOR_ENTITY_ID: string;
      TRUSTED_WALLET_PROVIDER_ISSUERS: readonly string[];
      CREDENTIAL_IDENTIFIERS: string[];
      CREDENTIAL_OFFER_URI: string | undefined;
    };
  }
}

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();
    const issuerConfig = config['credential-issuer'];
    const trustAnchorConfig = config['trust-anchor'];

    const baseURL = issuerConfig.url;
    const credentialIdentifiers = issuerConfig.credential_identifiers;

    let credentialOfferUri: string | undefined;
    if (credentialIdentifiers.length > 0) {
      validateCredentialIdentifiers(credentialIdentifiers, [...SUPPORTED_CREDENTIAL_CONFIGURATION_IDS]);
      credentialOfferUri = createCredentialOfferUri(buildCredentialOffer(baseURL, credentialIdentifiers));
    }

    app.decorate('config', {
      AUTH_FLOW: issuerConfig.auth_flow,
      BASE_URL: baseURL,
      BATCH_ISSUANCE_BY_DEFERRED: issuerConfig.batch_issuance_by_deferred,
      CREDENTIAL_IDENTIFIERS: credentialIdentifiers,
      CREDENTIAL_OFFER_URI: credentialOfferUri,
      DATA_DIR: config.global.data_dir,
      TRUST_ANCHOR_ENTITY_ID: trimTrailingSlashes(trustAnchorConfig.url.trim()),
      TRUSTED_WALLET_PROVIDER_ISSUERS: issuerConfig.trusted_wallet_provider_issuers
    });
  },

  { name: 'config' }
);
