import type { DisclosureFrame } from '@sd-jwt/types';

import { FakeUser } from '@/domain/faker';
import { createSRIHash, createSignerVerifier } from '@/domain/sd-jwt';
import { JwksRepository } from '@/domain/signer';
import { STATUS_LIST_URI } from '@/domain/utils/status-list';
import { JwkPublicKey } from '@/domain/z-jwk';
import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';

/**
 * Creates a signed SD-JWT credential for the specified holder.
 *
 * @param {string} iss - The issuer identifier (usually a URL).
 * @param {JwksRepository} jwksRepository - The repository containing issuer signing keys.
 * @param {JwkPublicKey} holderPublicKey - The public key of the credential holder.
 * @returns {Promise<string>} - A promise that resolves to the encoded SD-JWT credential.
 *
 * @example
 * const credential = await createSdJwt("https://issuer.example", jwksRepo, holderKey);
 */
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

  // Create SDJwt instance for use
  const sdjwt = new SDJwtVcInstance({
    hashAlg: 'sha-256',
    hasher: digest,
    saltGenerator: generateSalt,
    signAlg: ES256.alg,
    signer,
    verifier
  });

  const now = new Date();
  const expiration = new Date(now.getTime() + 24 * 60 * 60 * 1000 * 355); // plus 1 year
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

  // Issuer Define the disclosure frame to specify which claims can be disclosed
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
  const credentialSubject =
    config.isVersion(ItWalletSpecsVersion.V1_3) && 'sub' in claims ? claims.sub : holderPublicKey.kid;

  // Issue a signed JWT credential with the specified claims and disclosures
  // Return a Encoded SD JWT. Issuer send the credential to the holder
  const credential = await sdjwt.issue(
    {
      cnf: { jwk: holderPublicKey },
      exp: Math.floor(expiration.getTime() / 1000),
      iat,
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
      // verification
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
