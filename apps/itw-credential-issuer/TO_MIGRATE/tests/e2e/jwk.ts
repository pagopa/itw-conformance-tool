// ============================================================================
// Mock Keys (JWK)
// ============================================================================

import { toPublicJwk } from '@/domain/crypto';

export const dpopJwk = {
  crv: 'P-256',
  d: 'IfSdct8njqWDcMaLIO3ZGG-8a61t9acXxxFWFVDFx6Y',
  kid: '_2WG3zgh4XGrlTCK9QkPoGS-pqAvmg5CcGH_m4eve2e',
  kty: 'EC',
  x: 'ghHo8AZRPhIdmR9zO_aab0R7CsDah-XI5zht8GXo71w',
  y: 'Xfx_VfGzNfRVT5cNbi8jKZ3KMgKzqPGHWCT1yklA0UE'
};

export const requestProofJwk = {
  crv: 'P-256',
  d: 'b3T5vRCtRPk-iWQs1qZiCH8pmfUp3g6HfobJi4gHKX8',
  kid: '_1WG3zgh4XGrlTCK9QkPoGS-pqAvmg5CcGH_m4eve2e',
  kty: 'EC',
  x: 'ILLpnBYABwKEgkSLnX7Py8jP6MpcQO6t5u232iOdcz8',
  y: 'II3uHcxF5ve3VFtUb1ZGWIxVMyLhynRHDnJa2WPXj9E'
};

export const accessTokenJwk = {
  crv: 'P-256',
  d: 'Y2KgM6WsS5lAiZMj96VaqPm0YpP67mclJ5yXbhM7oQE',
  kty: 'EC',
  x: 'kazsvNpTiwE4mB6k-uLHNfexl_UysiJqNvDRO6SZE1A',
  y: 'VnWF5YzCR5ZWiugFM4rxPDviOWmMXU4pUVCRAdz-uLI'
};

export const walletProviderJwk = {
  crv: 'P-256',
  d: 'lsw0CsYcKEGm5kyt9912wVs5DvjyWV4bUe6TlfzVyJo',
  kid: 'kzouDFz7NlhG_cW00MX_e5bfmGmMRCH4UOxzy16TqJY',
  kty: 'EC',
  x: '3KZRbvgZTDt6NgAbg8zHJtjQS6FHD6WeOEC7YbI-Z54',
  y: '5NSHUaYbU25tXq7mJpCoXUFmiN5bKueO_6PMsQ4rpSI'
};

export const dpopJwkPublic = toPublicJwk(dpopJwk);
export const requestProofJwkPublic = toPublicJwk(requestProofJwk);
export const accessTokenJwkPublic = toPublicJwk(accessTokenJwk);
export const walletProviderJwkPublic = toPublicJwk(walletProviderJwk);
