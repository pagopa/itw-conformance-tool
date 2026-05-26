import { randomBytes, randomUUID } from 'node:crypto';

import { importJWK, SignJWT } from 'jose';

import type { IPARRepository } from '@itw-conformance-tool/database';
import type { JwksRepository, MockIdentity, MrtdAuthSession, ParRequest } from '@itw-conformance-tool/issuer';

const MOCK_IDENTITY: MockIdentity = {
  birthdate: '1990-12-12',
  family_name: 'Rossi',
  given_name: 'Mario',
  personal_administrative_number: 'RSSMRA90T12H501U',
  place_of_birth: {
    country: 'IT',
    locality: 'Roma',
    region: 'RM'
  }
};

type MrtdChallengePayload = {
  htu: string;
  mrtd_auth_session: string;
  mrtd_pop_jwt_nonce: string;
  state: string;
  status: 'pending_mrtd_init';
};

export class MockIdpRequestError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'MockIdpRequestError';
    this.statusCode = statusCode;
    Object.setPrototypeOf(this, MockIdpRequestError.prototype);
  }
}

export type MockIdpAuthorizeOptions = {
  readonly baseURL: string;
  readonly requestUri: string;
};

export type MockIdpAuthorizeResult = {
  readonly location: string;
};

export class MockIdpService {
  readonly #parRepository: IPARRepository;
  readonly #jwksRepository: JwksRepository;

  constructor(parRepository: IPARRepository, jwksRepository: JwksRepository) {
    this.#parRepository = parRepository;
    this.#jwksRepository = jwksRepository;
  }

  async authorize(options: MockIdpAuthorizeOptions): Promise<MockIdpAuthorizeResult> {
    const parRequest = await this.#getParRequest(options.requestUri);

    if (!parRequest.redirect_uri || !parRequest.state) {
      throw new MockIdpRequestError('PAR request is missing redirect_uri/state', 400);
    }

    if (parRequest.pid_auth_flow === 'l3') {
      return await this.#authorizeL3(parRequest, options);
    }

    if (parRequest.pid_auth_flow === 'l2plus') {
      return await this.#authorizeL2Plus(parRequest, options);
    }

    throw new MockIdpRequestError('PAR request is not configured for mock IdP flow', 400);
  }

  async #getParRequest(requestUri: string): Promise<ParRequest> {
    const entry = await this.#parRepository.get(requestUri);
    if (!entry) {
      throw new MockIdpRequestError('request_uri not found', 400);
    }

    return JSON.parse(entry.requestObject) as ParRequest;
  }

  async #authorizeL3(parRequest: ParRequest, options: MockIdpAuthorizeOptions): Promise<MockIdpAuthorizeResult> {
    const code = randomUUID();
    const codeExpiresAt = Math.floor(Date.now() / 1000) + 60;

    const updatedParRequest = {
      ...parRequest,
      code,
      code_consumed_at: undefined,
      code_expires_at: codeExpiresAt,
      mock_identity: MOCK_IDENTITY,
      mock_loa: 'high' as const
    };

    await this.#parRepository.update(options.requestUri, {
      requestObject: JSON.stringify(updatedParRequest)
    });

    const location = new URL(parRequest.redirect_uri);
    location.searchParams.set('code', code);
    location.searchParams.set('state', parRequest.state);
    location.searchParams.set('iss', options.baseURL);

    return {
      location: location.toString()
    };
  }

  async #authorizeL2Plus(parRequest: ParRequest, options: MockIdpAuthorizeOptions): Promise<MockIdpAuthorizeResult> {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 300;
    const mrtdAuthSessionId = randomUUID();
    const mrtdPopJwtNonce = randomBytes(16).toString('hex');

    const payload: MrtdChallengePayload = {
      htu: new URL('/edoc-proof/init', options.baseURL).toString(),
      mrtd_auth_session: mrtdAuthSessionId,
      mrtd_pop_jwt_nonce: mrtdPopJwtNonce,
      state: parRequest.state,
      status: 'pending_mrtd_init'
    };
    const challengeInfo = await this.#createMrtdChallengeInfo(payload, expiresAt, now);

    const mrtdAuthSession: MrtdAuthSession = {
      auth_flow: 'l2plus',
      challenge: challengeInfo,
      created_at: now,
      expires_at: expiresAt,
      identity: MOCK_IDENTITY,
      mrtd_auth_session: mrtdAuthSessionId,
      mrtd_pop_jwt_nonce: mrtdPopJwtNonce,
      status: 'pending_mrtd_init'
    };

    const updatedParRequest = {
      ...parRequest,
      code: undefined,
      code_consumed_at: undefined,
      code_expires_at: undefined,
      mock_identity: MOCK_IDENTITY,
      mock_loa: 'substantial' as const,
      mrtd_auth_session: mrtdAuthSession
    };

    await this.#parRepository.update(options.requestUri, {
      requestObject: JSON.stringify(updatedParRequest)
    });

    const location = new URL(parRequest.redirect_uri);
    location.searchParams.set('challenge_info', challengeInfo);
    location.searchParams.set('state', parRequest.state);

    return {
      location: location.toString()
    };
  }

  async #createMrtdChallengeInfo(payload: MrtdChallengePayload, exp: number, iat: number): Promise<string> {
    const { private: privateSig, public: publicSig } = this.#jwksRepository.getSign();
    const signAlgorithm = 'ES256';
    const key = await importJWK(privateSig, signAlgorithm);

    return await new SignJWT(payload)
      .setProtectedHeader({
        alg: signAlgorithm,
        kid: publicSig.kid,
        typ: 'mrtd-ias+jwt'
      })
      .setIssuer('mock-idp')
      .setIssuedAt(iat)
      .setExpirationTime(exp)
      .sign(key);
  }
}
