import { ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { describe, expect, it } from 'vitest';

import { dc_sd_jwt_PersonIdentificationData, mso_mdoc_PersonIdentificationData } from '../credential-configurations';

describe('PID credential configurations', () => {
  it('advertises the V1_3 SD-JWT PID claims', () => {
    const configuration = dc_sd_jwt_PersonIdentificationData('https://issuer.example', ItWalletSpecsVersion.V1_3);

    expect(configuration.vct).toBe('urn:eudi:pid:it:1');
    expect(configuration.claims).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          mandatory: true,
          path: ['birthdate'],
          value_type: 'date'
        }),
        expect.objectContaining({
          mandatory: true,
          path: ['place_of_birth'],
          value_type: 'place_of_birth'
        }),
        expect.objectContaining({
          mandatory: true,
          path: ['personal_administrative_number'],
          value_type: 'string'
        }),
        expect.objectContaining({
          mandatory: true,
          path: ['nationalities'],
          value_type: 'array'
        })
      ])
    );
  });

  it('advertises the V1_3 mdoc PID claims across both namespaces', () => {
    const configuration = mso_mdoc_PersonIdentificationData('https://issuer.example', ItWalletSpecsVersion.V1_3);

    expect(configuration.doctype).toBe('eu.europa.ec.eudi.pid.1');
    expect(configuration.claims).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ['eu.europa.ec.eudi.pid.1', 'place_of_birth'],
          value_type: 'place_of_birth'
        }),
        expect.objectContaining({
          path: ['eu.europa.ec.eudi.pid.1', 'nationality'],
          value_type: 'array'
        }),
        expect.objectContaining({
          mandatory: true,
          path: ['eu.europa.ec.eudi.pid.it.1', 'personal_administrative_number']
        }),
        expect.objectContaining({
          mandatory: true,
          path: ['eu.europa.ec.eudi.pid.it.1', 'sub']
        }),
        expect.objectContaining({
          mandatory: true,
          path: ['eu.europa.ec.eudi.pid.it.1', 'verification'],
          value_type: 'verification'
        })
      ])
    );
    expect(configuration.claims).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ['eu.europa.ec.eudi.pid.1', 'issue_date']
        })
      ])
    );
  });
});
