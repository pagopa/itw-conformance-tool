import { convertPemToBase64Der } from '@itw-conformance-tool/crypto';
import { type StatusListJWTHeaderParameters, createHeaderAndPayload } from '@sd-jwt/jwt-status-list';
import { type JWTPayload, SignJWT, importJWK } from 'jose';

import { STATUS_LIST_TTL_SECONDS } from '../models/status-list.js';
import { STATUS_LIST_BITS, STATUS_LIST_DEFAULT, STATUS_LIST_URI, createStatusList } from '../utils/status-list.js';

import type { JwksRepository } from '../signer.js';
import type { BitsPerStatus } from '@sd-jwt/jwt-status-list';

export interface StatusListSettings {
  bits: BitsPerStatus;
  values: number[];
}

export class StatusListService {
  private readonly jwksRepository: JwksRepository;

  constructor(jwksRepository: JwksRepository) {
    this.jwksRepository = jwksRepository;
  }

  async getStatusListJwt(
    baseURL: string,
    settings: StatusListSettings = DEFAULT_STATUS_LIST_SETTINGS
  ): Promise<string> {
    const statusList = createStatusList(settings.values, settings.bits);
    const lst = statusList.compressStatusList();

    const now = Math.floor(Date.now() / 1000);
    const payload: JWTPayload = {
      exp: now + STATUS_LIST_TTL_SECONDS,
      iat: now,
      iss: baseURL,
      status_list: { bits: settings.bits, lst },
      sub: STATUS_LIST_URI(baseURL),
      ttl: STATUS_LIST_TTL_SECONDS
    };

    const { private: privateSig } = this.jwksRepository.getSign();
    const header: StatusListJWTHeaderParameters = {
      alg: 'ES256',
      typ: 'statuslist+jwt',
      x5c: this.jwksRepository.issuerCertificateChain().map(convertPemToBase64Der)
    };

    const values = createHeaderAndPayload(statusList, payload, header);
    const signingKey = await importJWK(privateSig);

    return await new SignJWT(values.payload as Record<string, unknown>)
      .setProtectedHeader(values.header as { alg: string } & Record<string, unknown>)
      .sign(signingKey);
  }
}

export const DEFAULT_STATUS_LIST_SETTINGS = {
  bits: STATUS_LIST_BITS,
  values: STATUS_LIST_DEFAULT
} satisfies StatusListSettings;
