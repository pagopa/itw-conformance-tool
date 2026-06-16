import { convertPemToBase64Der, createSelfSignedCertificateFromJwk } from '@itw-conformance-tool/crypto';
import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';

import { createSRIHash, createSignerVerifier } from '../sd-jwt.js';
import { createBase64Portrait } from '../utils/portrait.js';
import { STATUS_LIST_URI } from '../utils/status-list.js';
import { DISABILITY_CARD_SCOPE, DISABILITY_CARD_VCT } from '../z-credential.js';

import type { FakeUser } from '../faker.js';
import type { JwksRepository } from '../signer.js';
import type { JwkPublicKey } from '../z-jwk.js';
import type { DisclosureFrame } from '@sd-jwt/types';

export { DISABILITY_CARD_SCOPE, DISABILITY_CARD_VCT };
export const DISABILITY_CARD_ID = 'dc_sd_jwt_EuropeanDisabilityCard';

export async function createDisabilityCardCredential(
  iss: string,
  jwksRepository: JwksRepository,
  holderPublicKey: JwkPublicKey,
  config: IoWalletSdkConfig,
  fakeUser: FakeUser
): Promise<string> {
  const jwks = jwksRepository.getSign();

  const [signer, verifier] = await createSignerVerifier({
    privateKey: jwks.private,
    publicKey: jwks.public
  });

  const sdjwt = new SDJwtVcInstance({
    hashAlg: 'sha-256',
    hasher: digest,
    saltGenerator: generateSalt,
    signAlg: ES256.alg,
    signer,
    verifier
  });

  const now = new Date();
  const expiration = new Date(now.getTime() + 24 * 60 * 60 * 1000 * 355);

  const claims = {
    birth_date: fakeUser.birthDate,
    constant_attendance_allowance: true,
    document_number: fakeUser.documentNumber,
    expiry_date: expiration.toISOString().slice(0, 10),
    family_name: fakeUser.familyName,
    given_name: fakeUser.givenName,
    issuing_authority: 'PagoPA S.p.A.',
    issuing_country: 'IT',
    link_qr_code: `https://example.com/verify?vc=${fakeUser.documentNumber}`,
    personal_administrative_number: fakeUser.fiscalCode,
    portrait: createBase64Portrait()
  };

  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: [
      'birth_date',
      'constant_attendance_allowance',
      'document_number',
      'expiry_date',
      'family_name',
      'given_name',
      'link_qr_code',
      'personal_administrative_number',
      'portrait'
    ]
  };

  const vctIntegrity = createSRIHash(DISABILITY_CARD_VCT);
  const subject = holderPublicKey.kid;
  if (typeof subject !== 'string' || subject.trim() === '') {
    throw new Error('Unable to issue disability card credential: missing subject identifier');
  }

  const signingCertificatePem = await createSelfSignedCertificateFromJwk(jwks.private);

  const credential = await sdjwt.issue(
    {
      cnf: { jwk: holderPublicKey },
      exp: Math.floor(expiration.getTime() / 1000),
      iat: Math.floor(now.getTime() / 1000),
      iss,
      status: {
        ...(config.isVersion(ItWalletSpecsVersion.V1_0) && {
          status_assertion: { credential_hash_alg: 'sha-256' }
        }),
        status_list: {
          idx: 1,
          uri: STATUS_LIST_URI(iss)
        }
      },
      sub: subject,
      vct: DISABILITY_CARD_VCT,
      'vct#integrity': vctIntegrity,
      ...claims
    },
    disclosureFrame,
    {
      header: {
        kid: jwks.private.kid,
        typ: 'dc+sd-jwt',
        x5c: [convertPemToBase64Der(signingCertificatePem)]
      }
    }
  );

  return credential;
}
