import { randomUUID } from 'node:crypto';

import { SignJWT, importJWK } from 'jose';

import { AUTHORIZATION_CODE_TTL_SECONDS } from '../models/token.js';
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

export class InvalidRequestUriError extends Error {
  constructor(requestUri: string) {
    super(`request_uri not found: ${requestUri}`);
    this.name = 'InvalidRequestUriError';
    Object.setPrototypeOf(this, InvalidRequestUriError.prototype);
  }
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
      throw new InvalidRequestUriError(requestUri);
    }

    const code = randomUUID();
    const codeExpiresAt = Math.floor(Date.now() / 1000) + AUTHORIZATION_CODE_TTL_SECONDS;

    const { private: privateSig } = this.jwksRepository.getSign();
    const importSig = await importJWK(privateSig);

    const jwt = await new SignJWT({
      code,
      ...(parEntry.state ? { state: parEntry.state } : {})
    })
      .setIssuer(this.baseURL)
      .setIssuedAt()
      .setExpirationTime(codeExpiresAt)
      .setProtectedHeader({ alg: 'ES256' })
      .sign(importSig);

    await this.parRepository.setCode(requestUri, code, codeExpiresAt);

    return {
      formPost: getFormPostFromRedirectUriAndJwt(parEntry.redirectUri, jwt),
      redirectUri: parEntry.redirectUri
    };
  }
}
