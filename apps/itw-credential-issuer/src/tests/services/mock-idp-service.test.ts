import { importJWK, jwtVerify } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';

import { generateJwks } from '../../crypto/auto-keygen.js';
import { MockIdpRequestError, MockIdpService } from '../../services/mock-idp-service.js';

import type { IPARRepository, PAREntry } from '@itw-conformance-tool/database';
import type { JwksRepository } from '@itw-conformance-tool/issuer';

const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:abc';
const BASE_URL = 'http://issuer.example.org';

let signingJwks: { keys: Array<Record<string, unknown>> };

beforeAll(async () => {
  signingJwks = JSON.parse(await generateJwks()) as { keys: Array<Record<string, unknown>> };
});

function createJwksRepository(): JwksRepository {
  const sign = signingJwks.keys.find((key) => key.kty === 'EC' && (key.use === 'sig' || key.use === undefined));
  const enc = signingJwks.keys.find((key) => key.kty === 'EC' && key.use === 'enc');

  if (!sign || !enc) {
    throw new Error('Expected generated JWKS to include EC sign and enc keys');
  }

  const { d: _signD, ...signPublicRaw } = sign as Record<string, unknown>;
  void _signD;
  const { d: _encD, ...encPublicRaw } = enc as Record<string, unknown>;
  void _encD;

  return {
    getEncrypt: () => ({
      private: enc as ReturnType<JwksRepository['getEncrypt']>['private'],
      public: encPublicRaw as unknown as ReturnType<JwksRepository['getEncrypt']>['public']
    }),
    getSign: () => ({
      private: sign as ReturnType<JwksRepository['getSign']>['private'],
      public: signPublicRaw as unknown as ReturnType<JwksRepository['getSign']>['public']
    }),
    iacaX509: () => 'CERT'
  };
}

function createParRepository(entry: PAREntry | undefined) {
  const get = vi.fn(async () => entry);
  const update = vi.fn(async () => undefined);

  const repository: IPARRepository = {
    delete: async () => undefined,
    get,
    insert: async () => undefined,
    update
  };

  return {
    get,
    repository,
    update
  };
}

describe('MockIdpService', () => {
  it('returns standard authorization code redirect for l3 flow', async () => {
    const parRequest = {
      authorization_details: [{ credential_configuration_id: 'dc_sd_jwt_PersonIdentificationData', type: 'openid_credential' }],
      client_id: 'wallet-client',
      id: '1',
      pid_auth_flow: 'l3',
      redirect_uri: 'https://wallet.example/cb',
      request_uri: REQUEST_URI,
      response_type: 'code',
      state: 'state-123'
    };
    const { repository, update } = createParRepository({
      clientId: parRequest.client_id,
      expiresAt: Date.now() + 60_000,
      requestObject: JSON.stringify(parRequest),
      requestUri: REQUEST_URI
    });

    const service = new MockIdpService(repository, createJwksRepository());
    const result = await service.authorize({ baseURL: BASE_URL, requestUri: REQUEST_URI });

    const location = new URL(result.location);
    expect(location.origin + location.pathname).toBe('https://wallet.example/cb');
    expect(location.searchParams.get('code')).toBeTruthy();
    expect(location.searchParams.get('state')).toBe('state-123');
    expect(location.searchParams.get('iss')).toBe(BASE_URL);

    expect(update).toHaveBeenCalledOnce();
    const [, updateData] = update.mock.calls[0] as unknown as [string, { requestObject: string }];
    const updatedPar = JSON.parse(updateData.requestObject) as Record<string, unknown>;
    expect(updatedPar.mock_loa).toBe('high');
    expect(updatedPar.mock_identity).toMatchObject({
      family_name: 'Rossi',
      given_name: 'Mario',
      personal_administrative_number: 'RSSMRA90T12H501U'
    });
    expect(updatedPar.code).toBeTruthy();
    expect(updatedPar.code_expires_at).toBeTypeOf('number');
  });

  it('returns challenge_info redirect and initializes mrtd session for l2plus flow', async () => {
    const parRequest = {
      authorization_details: [{ credential_configuration_id: 'dc_sd_jwt_PersonIdentificationData', type: 'openid_credential' }],
      client_id: 'wallet-client',
      id: '1',
      pid_auth_flow: 'l2plus',
      redirect_uri: 'https://wallet.example/cb',
      request_uri: REQUEST_URI,
      response_type: 'code',
      state: 'state-456'
    };
    const { repository, update } = createParRepository({
      clientId: parRequest.client_id,
      expiresAt: Date.now() + 60_000,
      requestObject: JSON.stringify(parRequest),
      requestUri: REQUEST_URI
    });
    const jwksRepository = createJwksRepository();

    const service = new MockIdpService(repository, jwksRepository);
    const result = await service.authorize({ baseURL: BASE_URL, requestUri: REQUEST_URI });

    const location = new URL(result.location);
    expect(location.origin + location.pathname).toBe('https://wallet.example/cb');
    expect(location.searchParams.get('state')).toBe('state-456');
    expect(location.searchParams.get('challenge_info')).toBeTruthy();

    expect(update).toHaveBeenCalledOnce();
    const [, updateData] = update.mock.calls[0] as unknown as [string, { requestObject: string }];
    const updatedPar = JSON.parse(updateData.requestObject) as Record<string, unknown>;
    expect(updatedPar.mock_loa).toBe('substantial');
    expect(updatedPar.code).toBeUndefined();

    const mrtdAuthSession = updatedPar.mrtd_auth_session as Record<string, unknown>;
    expect(mrtdAuthSession.status).toBe('pending_mrtd_init');
    expect(mrtdAuthSession.auth_flow).toBe('l2plus');
    expect(typeof mrtdAuthSession.mrtd_auth_session).toBe('string');
    expect(typeof mrtdAuthSession.mrtd_pop_jwt_nonce).toBe('string');
    expect(typeof mrtdAuthSession.challenge).toBe('string');

    const { public: publicSignJwk } = jwksRepository.getSign();
    const publicKey = await importJWK(publicSignJwk, 'ES256');
    const verified = await jwtVerify(String(mrtdAuthSession.challenge), publicKey);

    const payload = verified.payload as Record<string, unknown>;
    expect(payload.status).toBe('pending_mrtd_init');
    expect(payload.state).toBe('state-456');
    expect(payload.htu).toBe(new URL('/edoc-proof/init', BASE_URL).toString());
    expect(payload.mrtd_auth_session).toBe(mrtdAuthSession.mrtd_auth_session);
    expect(payload.mrtd_pop_jwt_nonce).toBe(mrtdAuthSession.mrtd_pop_jwt_nonce);
    expect(verified.protectedHeader.typ).toBe('mrtd-ias+jwt');
  });

  it('throws invalid_request when PAR entry does not exist', async () => {
    const { repository } = createParRepository(undefined);
    const service = new MockIdpService(repository, createJwksRepository());

    await expect(service.authorize({ baseURL: BASE_URL, requestUri: REQUEST_URI })).rejects.toBeInstanceOf(
      MockIdpRequestError
    );
  });
});
