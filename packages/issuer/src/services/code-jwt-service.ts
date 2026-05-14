import { randomUUID } from 'node:crypto';

import { SignJWT, importJWK } from 'jose';

import { getFormPostFromRedirectUriAndJwt } from '../utils/form-post-jwt.js';

import type { JwksRepository } from '../signer.js';

export interface ICodeJwtParEntry {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly requestUri: string;
  readonly state?: string;
}

export interface ICodeJwtParRepository {
  readonly get: (requestUri: string) => Promise<ICodeJwtParEntry | undefined>;
  readonly setCode: (requestUri: string, code: string, codeExpiresAt: number) => Promise<void>;
}

export interface CreateAuthorizationCodeJwtResult {
  readonly formPost: string;
  readonly redirectUri: string;
}

export class CodeJwtService {
  private readonly baseURL: string;
  private readonly jwksRepository: JwksRepository;
  private readonly parRepository: ICodeJwtParRepository;

  constructor(opts: { baseURL: string; jwksRepository: JwksRepository; parRepository: ICodeJwtParRepository }) {
    this.baseURL = opts.baseURL;
    this.jwksRepository = opts.jwksRepository;
    this.parRepository = opts.parRepository;
  }

  async createAuthorizationCodeJwt(requestUri: string): Promise<CreateAuthorizationCodeJwtResult> {
    const parEntry = await this.parRepository.get(requestUri);

    if (!parEntry) {
      throw new Error('request_uri not found');
    }

    const code = randomUUID();
    const codeExpiresAt = Math.floor(Date.now() / 1000) + 300;

    const { private: privateSig } = this.jwksRepository.getSign();
    const importSig = await importJWK(privateSig);

    const jwt = await new SignJWT({
      code,
      ...(parEntry.state ? { state: parEntry.state } : {})
    })
      .setIssuer(this.baseURL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .setProtectedHeader({ alg: 'ES256' })
      .sign(importSig);

    await this.parRepository.setCode(requestUri, code, codeExpiresAt);

    return {
      formPost: getFormPostFromRedirectUriAndJwt(parEntry.redirectUri, jwt),
      redirectUri: parEntry.redirectUri
    };
  }
}
