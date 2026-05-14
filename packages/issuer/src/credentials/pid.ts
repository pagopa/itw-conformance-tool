import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';

import { createSRIHash, createSignerVerifier } from '../sd-jwt.js';
import { STATUS_LIST_URI } from '../utils/status-list.js';

import type { FakeUser } from '../faker.js';
import type { JwksRepository } from '../signer.js';
import type { JwkPublicKey } from '../z-jwk.js';
import type { DisclosureFrame } from '@sd-jwt/types';

export const createPidCredential = async (
  iss: string,
  jwksRepository: JwksRepository,
  holderPublicKey: JwkPublicKey,
  config: IoWalletSdkConfig,
  fakeUser: FakeUser
): Promise<string> => {
  const jwks = jwksRepository.getSign();

  const [signer, verifier] = await createSignerVerifier({
    privateKey: jwks.private,
    publicKey: holderPublicKey
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
  const iat = Math.floor(now.getTime() / 1000);

  const baseClaims = {
    family_name: fakeUser.familyName,
    given_name: fakeUser.givenName,
    iat,
    issuing_authority: 'PagoPA S.p.A.',
    issuing_country: 'IT',
    nationalities: ['IT'],
    personal_administrative_number: fakeUser.fiscalCode
  };

  const claims = config.isVersion(ItWalletSpecsVersion.V1_3)
    ? {
        ...baseClaims,
        birthdate: fakeUser.birthDate,
        date_of_expiry: expiration.toISOString().slice(0, 10),
        place_of_birth: {
          country: 'IT',
          locality: 'Roma',
          region: 'Lazio'
        },
        sub: fakeUser.id,
        verification: {
          assurance_level: 'high',
          trust_framework: 'it_cie'
        }
      }
    : {
        ...baseClaims,
        birth_date: fakeUser.birthDate,
        birth_place: fakeUser.birthPlace,
        expiry_date: expiration.toISOString().slice(0, 10)
      };

  const disclosureFrame: DisclosureFrame<typeof claims> = config.isVersion(ItWalletSpecsVersion.V1_3)
    ? {
        _sd: [
          'birthdate',
          'place_of_birth',
          'family_name',
          'date_of_expiry',
          'given_name',
          'nationalities',
          'personal_administrative_number',
          'iat',
          'sub',
          'verification'
        ]
      }
    : {
        _sd: [
          'birth_date',
          'birth_place',
          'family_name',
          'expiry_date',
          'given_name',
          'nationalities',
          'personal_administrative_number',
          'iat'
        ]
      };

  const vct = config.isVersion(ItWalletSpecsVersion.V1_3) ? 'urn:eudi:pid:it:1' : 'urn:eu.europa.ec.eudi:pid:1';
  const vctIntegrity = createSRIHash(vct);
  const credentialSubjectCandidate =
    config.isVersion(ItWalletSpecsVersion.V1_3) && 'sub' in claims ? claims.sub : holderPublicKey.kid;
  if (typeof credentialSubjectCandidate !== 'string' || credentialSubjectCandidate.trim() === '') {
    throw new Error('Unable to issue PID credential: missing subject identifier');
  }
  const credentialSubject = credentialSubjectCandidate;

  const credential = await sdjwt.issue(
    {
      cnf: { jwk: holderPublicKey },
      exp: Math.floor(expiration.getTime() / 1000),
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
      sub: credentialSubject,
      vct,
      'vct#integrity': vctIntegrity,
      ...claims
    },
    disclosureFrame,
    {
      header: {
        kid: jwks.private.kid,
        typ: 'dc+sd-jwt',
        x5c: [jwksRepository.iacaX509()]
      }
    }
  );

  return credential;
};
