import { type StatusListJWTHeaderParameters, createHeaderAndPayload } from '@sd-jwt/jwt-status-list';
import { type JWTPayload, SignJWT, importJWK } from 'jose';

import { STATUS_LIST_BITS, STATUS_LIST_DEFAULT, STATUS_LIST_URI, createStatusList } from '../utils/status-list.js';

import type { JwksRepository } from '../signer.js';

export class StatusListService {
  private readonly jwksRepository: JwksRepository;

  constructor(jwksRepository: JwksRepository) {
    this.jwksRepository = jwksRepository;
  }

  async getStatusListJwt(baseURL: string): Promise<string> {
    const statusList = createStatusList(STATUS_LIST_DEFAULT, STATUS_LIST_BITS);
    const lst = statusList.compressStatusList();

    const now = Math.floor(Date.now() / 1000);
    const payload: JWTPayload = {
      exp: now + 3600,
      iat: now,
      iss: baseURL,
      status_list: { bits: STATUS_LIST_BITS, lst },
      sub: STATUS_LIST_URI(baseURL),
      ttl: 3000,
    };

    const { private: privateSig } = this.jwksRepository.getSign();
    const header: StatusListJWTHeaderParameters = {
      alg: 'ES256',
      typ: 'statuslist+jwt',
      x5c: [this.jwksRepository.iacaX509()],
    };

    const values = createHeaderAndPayload(statusList, payload, header);
    const signingKey = await importJWK(privateSig);

    return await new SignJWT(values.payload as Record<string, unknown>)
      .setProtectedHeader(values.header as { alg: string } & Record<string, unknown>)
      .sign(signingKey);
  }
}
