import { AppRepository } from '@/app/repository';
import {
  getDecryptJweCallback,
  getEncryptJweCallback,
  getSignJwtCallback,
  callbacks as partialCallbacks
} from '@/domain/crypto';
import { CallbackContext } from '@pagopa/io-wallet-oauth2';
import { type IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

import { type Config, config } from './config';

export class AppContext {
  public readonly callbacks: CallbackContext;
  public readonly config: Config;
  public readonly repository: AppRepository;

  constructor(customConfig: Config = config) {
    this.config = customConfig;
    this.repository = new AppRepository();

    const encKeys = this.repository.jwks.getEncrypt();
    const signKeys = [this.repository.jwks.getSign().private];

    const callbacks = {
      ...partialCallbacks,
      decryptJwe: getDecryptJweCallback(encKeys.private),
      encryptJwe: getEncryptJweCallback(encKeys.public),
      fetch,
      signJwt: getSignJwtCallback(signKeys)
    } satisfies CallbackContext;

    this.callbacks = callbacks;
  }
}

export type RequestAppContext = {
  sdkConfig: IoWalletSdkConfig;
} & AppContext;

export const appContext = new AppContext();
