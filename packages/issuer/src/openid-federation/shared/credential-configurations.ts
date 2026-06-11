import { ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';

import { DISABILITY_CARD_SCOPE, DISABILITY_CARD_VCT } from '../../z-credential.js';

export const pidIdentification = 'PersonIdentificationData';

const PID_MDOC_DOCTYPE = 'eu.europa.ec.eudi.pid.1';
const PID_MDOC_NAMESPACE = 'eu.europa.ec.eudi.pid.1';
const PID_MDOC_IT_NAMESPACE = 'eu.europa.ec.eudi.pid.it.1';

export const dc_sd_jwt_PersonIdentificationData = (baseURL: string, specVersion: ItWalletSpecsVersion) => ({
  claims: [
    {
      display: [
        { locale: 'it-IT', name: 'Nome' },
        { locale: 'en-US', name: 'First Name' }
      ],
      mandatory: true,
      path: ['given_name'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Cognome' },
        { locale: 'en-US', name: 'Family Name' }
      ],
      mandatory: true,
      path: ['family_name'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Data di nascita' },
        { locale: 'en-US', name: 'Date of birth' }
      ],
      mandatory: true,
      path: specVersion === ItWalletSpecsVersion.V1_3 ? ['birthdate'] : ['birth_date'],
      value_type: 'date'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Luogo di nascita' },
        { locale: 'en-US', name: 'Place of birth' }
      ],
      mandatory: true,
      path: specVersion === ItWalletSpecsVersion.V1_3 ? ['place_of_birth'] : ['birth_place'],
      value_type: specVersion === ItWalletSpecsVersion.V1_3 ? 'place_of_birth' : 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Codice Fiscale' },
        { locale: 'en-US', name: 'Tax id code' }
      ],
      mandatory: true,
      path: ['personal_administrative_number'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Nazionalità' },
        { locale: 'en-US', name: 'Nationality' }
      ],
      mandatory: true,
      path: ['nationalities'],
      value_type: 'array'
    },
    ...(specVersion === ItWalletSpecsVersion.V1_3
      ? [
          {
            display: [
              { locale: 'it-IT', name: 'Data di scadenza' },
              { locale: 'en-US', name: 'Date of expiry' }
            ],
            mandatory: true,
            path: ['date_of_expiry'],
            value_type: 'string'
          },
          {
            display: [
              { locale: 'it-IT', name: 'Identificativo univoco' },
              { locale: 'en-US', name: 'Subject identifier' }
            ],
            mandatory: true,
            path: ['sub'],
            value_type: 'string'
          },
          {
            display: [
              { locale: 'it-IT', name: 'Verifica' },
              { locale: 'en-US', name: 'Verification' }
            ],
            mandatory: true,
            path: ['verification'],
            value_type: 'verification'
          }
        ]
      : [])
  ],
  credential_signing_alg_values_supported: ['ES256', 'ES384', 'ES512'],
  cryptographic_binding_methods_supported: ['jwk'],
  display: [
    {
      background_color: '#12107c',
      locale: 'it-IT',
      logo: { alt_text: 'logo', url: `${baseURL}/public/logo.svg` },
      name: 'PID Provider italiano',
      text_color: '#FFFFFF'
    },
    {
      background_color: '#12107c',
      locale: 'en-US',
      logo: { alt_text: 'logo', url: `${baseURL}/public/logo.svg` },
      name: 'Italian PID Provider',
      text_color: '#FFFFFF'
    }
  ],
  format: 'dc+sd-jwt',
  proof_types_supported: {
    jwt: { proof_signing_alg_values_supported: ['ES256', 'ES384', 'ES512'] }
  },
  scope: pidIdentification,
  vct: specVersion === ItWalletSpecsVersion.V1_3 ? 'urn:eudi:pid:it:1' : 'urn:eu.europa.ec.eudi:pid:1'
});

export const mso_mdoc_mDL = (baseURL: string) => ({
  claims: [
    {
      display: [
        { locale: 'it-IT', name: 'Nome' },
        { locale: 'en-US', name: 'First Name' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'given_name'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Cognome' },
        { locale: 'en-US', name: 'Family Name' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'family_name'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Data di nascita' },
        { locale: 'en-US', name: 'Date of Birth' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'birth_date'],
      value_type: 'date'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Luogo di nascita' },
        { locale: 'en-US', name: 'Place of birth' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'birth_place'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Maggiorenne' },
        { locale: 'en-US', name: 'Age over 18' }
      ],
      mandatory: false,
      path: ['org.iso.18013.5.1', 'age_over_18'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Numero di documento' },
        { locale: 'en-US', name: 'Document Number' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'document_number'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Categorie di veicoli' },
        { locale: 'en-US', name: 'Driving Privileges' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'driving_privileges'],
      value_type: 'driving_privileges'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Data di scadenza' },
        { locale: 'en-US', name: 'Expiry Date' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'expiry_date'],
      value_type: 'date'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Data di rilascio' },
        { locale: 'en-US', name: 'Issue Date' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'issue_date'],
      value_type: 'date'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Autorità di rilascio' },
        { locale: 'en-US', name: 'Issuing Authority' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'issuing_authority'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Paese di rilascio' },
        { locale: 'en-US', name: 'Issuing Country' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'issuing_country'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Foto' },
        { locale: 'en-US', name: 'Portrait' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'portrait'],
      value_type: 'jpeg'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Firma' },
        { locale: 'en-US', name: 'Signature Usual Mark' }
      ],
      mandatory: false,
      path: ['org.iso.18013.5.1', 'signature_usual_mark'],
      value_type: 'jpeg'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Segno distintivo UN' },
        { locale: 'en-US', name: 'UN Distinguishing Sign' }
      ],
      mandatory: true,
      path: ['org.iso.18013.5.1', 'un_distinguishing_sign'],
      value_type: 'string'
    }
  ],
  credential_signing_alg_values_supported: [-7, -9],
  cryptographic_binding_methods_supported: ['cose_key'],
  display: [
    {
      background_color: '#12107c',
      locale: 'it-IT',
      logo: { alt_text: 'logo', url: `${baseURL}/public/logo.svg` },
      name: 'Patente di Guida',
      text_color: '#FFFFFF'
    },
    {
      background_color: '#12107c',
      locale: 'en-US',
      logo: { alt_text: 'logo', url: `${baseURL}/public/logo.svg` },
      name: 'Mobile Driving License',
      text_color: '#FFFFFF'
    }
  ],
  doctype: 'org.iso.18013.5.1.mDL',
  format: 'mso_mdoc',
  proof_types_supported: {
    jwt: { proof_signing_alg_values_supported: ['ES256'] }
  },
  scope: 'org.iso.18013.5.1.mDL'
});

export const dc_sd_jwt_EuropeanDisabilityCard = (baseURL: string) => ({
  claims: [
    {
      display: [
        { locale: 'it-IT', name: 'Codice QR' },
        { locale: 'en-US', name: 'QR Code' }
      ],
      mandatory: true,
      path: ['link_qr_code'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Nome' },
        { locale: 'en-US', name: 'Name' }
      ],
      mandatory: true,
      path: ['given_name'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Cognome' },
        { locale: 'en-US', name: 'Family Name' }
      ],
      mandatory: true,
      path: ['family_name'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Codice Fiscale' },
        { locale: 'en-US', name: 'Tax Identification Number' }
      ],
      mandatory: true,
      path: ['personal_administrative_number'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Data di nascita' },
        { locale: 'en-US', name: 'Date of birth' }
      ],
      mandatory: true,
      path: ['birth_date'],
      value_type: 'date'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Data di scadenza' },
        { locale: 'en-US', name: 'Date of expiry' }
      ],
      mandatory: true,
      path: ['expiry_date'],
      value_type: 'date'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Numero' },
        { locale: 'en-US', name: 'License number' }
      ],
      mandatory: true,
      path: ['document_number'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Fotografia' },
        { locale: 'en-US', name: 'Portrait' }
      ],
      mandatory: true,
      path: ['portrait'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Indennità di assistenza continua' },
        { locale: 'en-US', name: 'Constant attendance allowance' }
      ],
      mandatory: true,
      path: ['constant_attendance_allowance'],
      value_type: 'boolean'
    }
  ],
  credential_signing_alg_values_supported: ['ES256', 'ES384', 'ES512'],
  cryptographic_binding_methods_supported: ['jwk'],
  display: [
    {
      background_color: '#0058A0',
      locale: 'it-IT',
      logo: { alt_text: 'logo', url: `${baseURL}/public/logo.svg` },
      name: 'Carta della disabilità europea',
      text_color: '#FFFFFF'
    },
    {
      background_color: '#0058A0',
      locale: 'en-US',
      logo: { alt_text: 'logo', url: `${baseURL}/public/logo.svg` },
      name: 'European Disability Card',
      text_color: '#FFFFFF'
    }
  ],
  format: 'dc+sd-jwt',
  proof_types_supported: {
    jwt: { proof_signing_alg_values_supported: ['ES256', 'ES384', 'ES512'] }
  },
  scope: DISABILITY_CARD_SCOPE,
  vct: DISABILITY_CARD_VCT
});

export const mso_mdoc_PersonIdentificationData = (baseURL: string, specVersion: ItWalletSpecsVersion) => ({
  claims: [
    {
      display: [
        { locale: 'it-IT', name: 'Nome' },
        { locale: 'en-US', name: 'First Name' }
      ],
      mandatory: true,
      path: [PID_MDOC_NAMESPACE, 'given_name'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Cognome' },
        { locale: 'en-US', name: 'Family Name' }
      ],
      mandatory: true,
      path: [PID_MDOC_NAMESPACE, 'family_name'],
      value_type: 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Data di nascita' },
        { locale: 'en-US', name: 'Date of birth' }
      ],
      mandatory: true,
      path: [PID_MDOC_NAMESPACE, 'birth_date'],
      value_type: 'date'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Luogo di nascita' },
        { locale: 'en-US', name: 'Place of birth' }
      ],
      mandatory: true,
      path:
        specVersion === ItWalletSpecsVersion.V1_3
          ? [PID_MDOC_NAMESPACE, 'place_of_birth']
          : [PID_MDOC_NAMESPACE, 'birth_place'],
      value_type: specVersion === ItWalletSpecsVersion.V1_3 ? 'place_of_birth' : 'string'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Nazionalità' },
        { locale: 'en-US', name: 'Nationality' }
      ],
      mandatory: true,
      path:
        specVersion === ItWalletSpecsVersion.V1_3
          ? [PID_MDOC_NAMESPACE, 'nationality']
          : [PID_MDOC_NAMESPACE, 'nationalities'],
      value_type: 'array'
    },
    {
      display: [
        { locale: 'it-IT', name: 'Data di scadenza' },
        { locale: 'en-US', name: 'Expiry Date' }
      ],
      mandatory: true,
      path: [PID_MDOC_NAMESPACE, 'expiry_date'],
      value_type: 'date'
    },
    ...(specVersion === ItWalletSpecsVersion.V1_3
      ? [
          {
            display: [
              { locale: 'it-IT', name: 'Codice Fiscale' },
              { locale: 'en-US', name: 'Tax id code' }
            ],
            mandatory: true,
            path: [PID_MDOC_IT_NAMESPACE, 'personal_administrative_number'],
            value_type: 'string'
          },
          {
            display: [
              { locale: 'it-IT', name: 'Identificativo univoco' },
              { locale: 'en-US', name: 'Subject identifier' }
            ],
            mandatory: true,
            path: [PID_MDOC_IT_NAMESPACE, 'sub'],
            value_type: 'string'
          },
          {
            display: [
              { locale: 'it-IT', name: 'Verifica' },
              { locale: 'en-US', name: 'Verification' }
            ],
            mandatory: true,
            path: [PID_MDOC_IT_NAMESPACE, 'verification'],
            value_type: 'verification'
          }
        ]
      : [
          {
            display: [
              { locale: 'it-IT', name: 'Codice Fiscale' },
              { locale: 'en-US', name: 'National tax identification code' }
            ],
            mandatory: false,
            path: [PID_MDOC_NAMESPACE, 'personal_administrative_number'],
            value_type: 'string'
          },
          {
            display: [
              { locale: 'it-IT', name: 'Data di rilascio' },
              { locale: 'en-US', name: 'Issue Date' }
            ],
            mandatory: true,
            path: [PID_MDOC_NAMESPACE, 'issue_date'],
            value_type: 'date'
          }
        ])
  ],
  credential_signing_alg_values_supported: [-7, -9],
  cryptographic_binding_methods_supported: ['cose_key'],
  display: [
    {
      background_color: '#12107c',
      locale: 'it-IT',
      logo: { alt_text: 'logo', url: `${baseURL}/public/logo.svg` },
      name: 'PID Provider italiano',
      text_color: '#FFFFFF'
    },
    {
      background_color: '#12107c',
      locale: 'en-US',
      logo: { alt_text: 'logo', url: `${baseURL}/public/logo.svg` },
      name: 'Italian PID Provider',
      text_color: '#FFFFFF'
    }
  ],
  doctype: PID_MDOC_DOCTYPE,
  format: 'mso_mdoc',
  proof_types_supported: {
    jwt: { proof_signing_alg_values_supported: ['ES256', 'ES384', 'ES512'] }
  },
  scope: pidIdentification
});
