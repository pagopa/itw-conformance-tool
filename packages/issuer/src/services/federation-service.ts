import { getFederationMetadata } from '../openid-federation/index.js';

import type { JwksRepository } from '../signer.js';
import type { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

export class FederationService {
  readonly #jwksRepository: JwksRepository;

  constructor(jwksRepository: JwksRepository) {
    this.#jwksRepository = jwksRepository;
  }

  getEntityConfiguration(baseURL: string, config: IoWalletSdkConfig, trustAnchorEntityId: string): Promise<string> {
    return getFederationMetadata({ baseURL, config, jwksRepository: this.#jwksRepository, trustAnchorEntityId });
  }
}
