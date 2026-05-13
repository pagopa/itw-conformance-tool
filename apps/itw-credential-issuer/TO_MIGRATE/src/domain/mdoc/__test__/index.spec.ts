import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { describe, expect, it } from 'vitest';

import type { FakeUser } from '../../faker';

import {
  BADGE_DOCTYPE,
  BADGE_NAMESPACE,
  MDL_DOCTYPE,
  MDL_NAMESPACE,
  PID_MDOC_DOCTYPE,
  PID_MDOC_IT_NAMESPACE,
  PID_MDOC_NAMESPACE,
  getMdocCredentialDefinition
} from '../index';

describe('getMdocCredentialDefinition()', () => {
  const configV1_3 = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_3
  });

  const configV1_0 = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0
  });

  const holderPublicKey = {
    crv: 'P-256',
    kid: 'holder-kid',
    kty: 'EC',
    x: 'holder-x',
    y: 'holder-y'
  } as const;

  const fakeUser: FakeUser = {
    birthDate: '1990-06-15',
    birthPlace: 'Rome (RM)',
    documentNumber: 'ABCDEFGHIJKLMNOPQR',
    familyName: 'Bianchi',
    fiscalCode: 'BNCMRA90H15H501V',
    givenName: 'Marco',
    id: 'fake-user-uuid-123'
  };

  it('returns the mDL document definition', () => {
    const definition = getMdocCredentialDefinition('mso_mdoc_mDL', configV1_3, holderPublicKey, fakeUser);

    expect(definition).toMatchObject({
      docType: MDL_DOCTYPE,
      namespaces: {
        [MDL_NAMESPACE]: expect.any(Object)
      }
    });
  });

  it('returns the company badge definition bound to the holder key', () => {
    const definition = getMdocCredentialDefinition('mso_mdoc_CompanyBadge', configV1_3, holderPublicKey, fakeUser);

    expect(definition).toMatchObject({
      docType: BADGE_DOCTYPE,
      namespaces: {
        [BADGE_NAMESPACE]: expect.any(Object)
      }
    });
    expect(definition?.namespaces[BADGE_NAMESPACE]?.sub).toBe('holder-kid');
  });

  it('returns the PID mdoc definition for V1_3', () => {
    const definition = getMdocCredentialDefinition(
      'mso_mdoc_PersonIdentificationData',
      configV1_3 as never,
      holderPublicKey,
      fakeUser
    );

    expect(definition).toMatchObject({
      docType: PID_MDOC_DOCTYPE,
      namespaces: {
        [PID_MDOC_IT_NAMESPACE]: {
          personal_administrative_number: fakeUser.fiscalCode,
          verification: {
            assurance_level: 'high',
            trust_framework: 'it_cie'
          }
        },
        [PID_MDOC_NAMESPACE]: {
          family_name: fakeUser.familyName,
          given_name: fakeUser.givenName,
          nationality: ['IT'],
          place_of_birth: {
            locality: 'Roma'
          }
        }
      }
    });
    expect(definition?.namespaces[PID_MDOC_IT_NAMESPACE]?.sub).toEqual(fakeUser.id);
    expect(definition?.namespaces[PID_MDOC_NAMESPACE]?.issue_date).toBeUndefined();
  });

  it('returns the legacy PID mdoc definition for V1_0', () => {
    const definition = getMdocCredentialDefinition(
      'mso_mdoc_PersonIdentificationData',
      configV1_0,
      holderPublicKey,
      fakeUser
    );

    expect(definition).toMatchObject({
      docType: PID_MDOC_DOCTYPE,
      namespaces: {
        [PID_MDOC_NAMESPACE]: {
          birth_place: 'Rome (RM)',
          nationalities: ['IT'],
          personal_administrative_number: fakeUser.fiscalCode
        }
      }
    });
    expect(definition?.namespaces[PID_MDOC_IT_NAMESPACE]).toBeUndefined();
  });
});
