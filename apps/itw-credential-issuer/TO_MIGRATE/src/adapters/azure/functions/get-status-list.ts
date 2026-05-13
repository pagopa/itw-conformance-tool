import { BITS, LIST, STATUS_LIST_URI, createStatusList } from '@/domain/utils/status-list';
import { HttpHandler } from '@azure/functions';
import { type StatusListJWTHeaderParameters, createHeaderAndPayload } from '@sd-jwt/jwt-status-list';
import { type JWTPayload, SignJWT, importJWK } from 'jose';

export const GetStatusListHandler: HttpHandler = async (_request, context) => {
  const baseURL = context.app.config.baseURL;
  const jwksRepository = context.app.repository.jwks;

  const statusList = createStatusList(LIST, BITS);
  const lst = statusList.compressStatusList();

  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    exp: now + 3600,
    iat: now,
    iss: baseURL,
    status_list: {
      bits: BITS,
      lst
    },
    sub: STATUS_LIST_URI(baseURL),
    ttl: 3000
  };

  const { private: privateSig } = jwksRepository.getSign();
  const header: StatusListJWTHeaderParameters = {
    alg: 'ES256',
    typ: 'statuslist+jwt',
    x5c: [jwksRepository.iacaX509()]
  };

  const values = createHeaderAndPayload(statusList, payload, header);
  const signingKey = await importJWK(privateSig);

  const jwt = await new SignJWT(values.payload).setProtectedHeader(values.header).sign(signingKey);

  return {
    body: jwt,
    headers: {
      'Content-Type': 'application/statuslist+jwt'
    },
    status: 200
  };
};
