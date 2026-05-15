import { DateOnly, hex } from '@owf/mdoc';

import { portrait } from '../../utils/portrait.js';

import type { FakeUser } from '../../faker.js';
import type { MdocDocumentDefinition } from './index.js';

export const BADGE_NAMESPACE = 'eu.europa.it.badge.1';
export const BADGE_DOCTYPE = 'eu.europa.it.badge';

export const getCompanyBadgeDocument = (holderKeyId: string, fakeUser: FakeUser): MdocDocumentDefinition => {
  const now = new Date();
  const expiration = new Date(now.getTime() + 24 * 60 * 60 * 1000 * 355);
  const expiryDate = expiration.toISOString().slice(0, 10);

  return {
    docType: BADGE_DOCTYPE,
    namespaces: {
      [BADGE_NAMESPACE]: {
        benefits: ['canteen', 'mobile'],
        birth_date: new DateOnly(fakeUser.birthDate),
        company: 'Fondazione Bruno Kessler',
        document_number: fakeUser.documentNumber,
        employee_code: '22343',
        expiry_date: new DateOnly(expiryDate),
        family_name: fakeUser.familyName,
        given_name: fakeUser.givenName,
        issuing_authority: 'PagoPA S.p.A.',
        issuing_country: 'IT',
        locations: ['Sommarive_ ST', 'Sommarive_OpenSpace1', 'Sommarive_ parcheggio'],
        portrait: hex.decode(portrait),
        qualifications: ['Safety_foreman', 'device_admin', 'server_admin'],
        roles: ['lab_specialist', 'researcher'],
        sub: holderKeyId,
        team: 'Security & Trust'
      }
    },
    validityInfo: {
      signed: now,
      validFrom: now,
      validUntil: expiration
    }
  };
};
