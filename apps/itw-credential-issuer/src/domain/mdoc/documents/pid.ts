import { DateOnly } from '@owf/mdoc';
import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';

import type { FakeUser } from '../../faker.js';
import type { MdocDocumentDefinition } from './index.js';

export const PID_MDOC_NAMESPACE = 'eu.europa.ec.eudi.pid.1';
export const PID_MDOC_IT_NAMESPACE = 'eu.europa.ec.eudi.pid.it.1';
export const PID_MDOC_DOCTYPE = 'eu.europa.ec.eudi.pid.1';

export const getPidMdocDocument = (config: IoWalletSdkConfig, fakeUser: FakeUser): MdocDocumentDefinition => {
  const now = new Date();
  const expiration = new Date(now.getTime() + 24 * 60 * 60 * 1000 * 355);
  const expiryDate = expiration.toISOString().slice(0, 10);

  return config.isVersion(ItWalletSpecsVersion.V1_3)
    ? {
        docType: PID_MDOC_DOCTYPE,
        namespaces: {
          [PID_MDOC_IT_NAMESPACE]: {
            personal_administrative_number: fakeUser.fiscalCode,
            sub: fakeUser.id,
            verification: {
              assurance_level: 'high',
              trust_framework: 'it_cie'
            }
          },
          [PID_MDOC_NAMESPACE]: {
            age_over_18: true,
            birth_date: new DateOnly(fakeUser.birthDate),
            expiry_date: new DateOnly(expiryDate),
            family_name: fakeUser.familyName,
            given_name: fakeUser.givenName,
            issuing_authority: 'PagoPA S.p.A.',
            issuing_country: 'IT',
            nationality: ['IT'],
            place_of_birth: {
              locality: 'Roma'
            }
          }
        },
        validityInfo: {
          signed: now,
          validFrom: now,
          validUntil: expiration
        }
      }
    : {
        docType: PID_MDOC_DOCTYPE,
        namespaces: {
          [PID_MDOC_NAMESPACE]: {
            age_over_18: true,
            birth_date: new DateOnly(fakeUser.birthDate),
            birth_place: fakeUser.birthPlace,
            expiry_date: new DateOnly(expiryDate),
            family_name: fakeUser.familyName,
            given_name: fakeUser.givenName,
            issue_date: now,
            issuing_authority: 'PagoPA S.p.A.',
            issuing_country: 'IT',
            nationalities: ['IT'],
            personal_administrative_number: fakeUser.fiscalCode
          }
        },
        validityInfo: {
          signed: now,
          validFrom: now,
          validUntil: expiration
        }
      };
};
