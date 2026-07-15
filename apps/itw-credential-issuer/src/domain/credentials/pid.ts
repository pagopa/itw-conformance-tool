import { convertPemToBase64Der } from '@itw-conformance-tool/crypto';
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
  fakeUser: FakeUser,
  authFlow?: string
): Promise<string> => {
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
  const iat = Math.floor(now.getTime() / 1000);

  const isMockFlow = authFlow === 'l2plus' || authFlow === 'l3';

  const baseClaims = {
    family_name: isMockFlow ? 'Rossi' : fakeUser.familyName,
    given_name: isMockFlow ? 'Mario' : fakeUser.givenName,
    iat,
    issuing_authority: 'PagoPA S.p.A.',
    issuing_country: 'IT',
    nationalities: ['IT'],
    personal_administrative_number: isMockFlow ? 'RSSMRA90T12H501U' : fakeUser.fiscalCode
  };

  const claims = config.isVersion(ItWalletSpecsVersion.V1_3)
    ? {
        ...baseClaims,
        birthdate: isMockFlow ? '1990-12-12' : fakeUser.birthDate,
        date_of_expiry: expiration.toISOString().slice(0, 10),
        place_of_birth: {
          country: 'IT',
          locality: isMockFlow ? 'Roma' : fakeUser.birthPlace.split(' (')[0],
          region: 'Lazio'
        },
        sub: fakeUser.id,
        verification: {
          assurance_level: authFlow === 'l2plus' ? 'substantial' : 'high',
          trust_framework: authFlow === 'l2plus' ? 'it_l2+document_proof' : 'it_cie'
        }
      }
    : {
        ...baseClaims,
        birth_date: isMockFlow ? '1990-12-12' : fakeUser.birthDate,
        birth_place: isMockFlow ? 'Roma' : fakeUser.birthPlace,
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
        x5c: jwksRepository.issuerCertificateChain().map(convertPemToBase64Der)
      }
    }
  );

  return credential;
};
