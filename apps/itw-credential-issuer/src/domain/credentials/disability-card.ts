import { convertPemToBase64Der } from '@itw-conformance-tool/crypto';
import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';

import { applyDigitalCredentialClaimsFault } from '../faults/digital-credential-claims-fault.js';
import { applyDigitalCredentialTrustChainFault } from '../faults/digital-credential-trust-chain-fault.js';
import { createSRIHash, createSignerVerifier } from '../sd-jwt.js';
import { createBase64Portrait } from '../utils/portrait.js';
import { STATUS_LIST_URI } from '../utils/status-list.js';
import { DISABILITY_CARD_SCOPE, DISABILITY_CARD_VCT } from '../z-credential.js';

import type { FakeUser } from '../faker.js';
import type {
  DigitalCredentialClaimsFaultMutationEvidence,
  DigitalCredentialClaimsFaultProfile
} from '../faults/digital-credential-claims-fault.js';
import type {
  DigitalCredentialTrustChainFaultMutationEvidence,
  DigitalCredentialTrustChainFaultProfile
} from '../faults/digital-credential-trust-chain-fault.js';
import type { JwksRepository } from '../signer.js';
import type { JwkPublicKey } from '../z-jwk.js';
import type { DisclosureFrame } from '@sd-jwt/types';

export { DISABILITY_CARD_SCOPE, DISABILITY_CARD_VCT };
export const DISABILITY_CARD_ID = 'dc_sd_jwt_EuropeanDisabilityCard';

export class DigitalCredentialClaimsFaultApplicationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DigitalCredentialClaimsFaultApplicationError';
    Object.setPrototypeOf(this, DigitalCredentialClaimsFaultApplicationError.prototype);
  }
}

export class DigitalCredentialTrustChainFaultApplicationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DigitalCredentialTrustChainFaultApplicationError';
    Object.setPrototypeOf(this, DigitalCredentialTrustChainFaultApplicationError.prototype);
  }
}

/**
 * The disability card credential builder's supported fault profiles, kept
 * as an explicit discriminated union (over `type`) so the WP_060 payload
 * mutation and the WP_061 JOSE-header mutation branch separately and can
 * never be active/applied together in the same issuance.
 */
export type DisabilityCardFaultProfile = DigitalCredentialClaimsFaultProfile | DigitalCredentialTrustChainFaultProfile;

export interface CreateDisabilityCardCredentialResult {
  credential: string;
  /** Present only when `activeFaultProfile` was provided and successfully applied. */
  faultEvidence?: DigitalCredentialClaimsFaultMutationEvidence | DigitalCredentialTrustChainFaultMutationEvidence;
}

export async function createDisabilityCardCredential(
  iss: string,
  jwksRepository: JwksRepository,
  holderPublicKey: JwkPublicKey,
  config: IoWalletSdkConfig,
  fakeUser: FakeUser,
  activeFaultProfile?: DisabilityCardFaultProfile
): Promise<CreateDisabilityCardCredentialResult> {
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

  // Assemble the complete unsigned payload first so an optional WP_060 fault
  // (see digital-credential-claims-fault.ts) can be applied to it before
  // signing, keeping the resulting SD-JWT VC validly signed while only its
  // semantic content is defective.
  const unsignedPayload = {
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
  };

  let payloadToSign: typeof unsignedPayload = unsignedPayload;
  let faultEvidence:
    DigitalCredentialClaimsFaultMutationEvidence | DigitalCredentialTrustChainFaultMutationEvidence | undefined;
  // Nominal x5c: the leaf certificate's public key always corresponds to
  // `jwks.private` (see `JwksRepository.issuerCertificateChain` docs).
  let x5c = jwksRepository.issuerCertificateChain().map(convertPemToBase64Der);

  if (activeFaultProfile?.type === 'digital-credential-claims-invalid') {
    const mutation = applyDigitalCredentialClaimsFault({ profile: activeFaultProfile, claims: unsignedPayload });
    if (!mutation.ok) {
      throw new DigitalCredentialClaimsFaultApplicationError(
        `Unable to apply the digital-credential-claims-invalid fault to the disability card credential: ${mutation.reason}`
      );
    }

    // The mutated claims may be missing `issuing_country` (schema-invalid
    // variant), so it is only structurally compatible with the nominal
    // payload type, not identical to it; the runtime shape is exactly what
    // the fault helper's own tests verify.
    payloadToSign = mutation.mutation.claims as typeof unsignedPayload;
    faultEvidence = mutation.mutation.evidence;
  } else if (activeFaultProfile?.type === 'edc-invalid-trust-chain') {
    // The payload/claims stay nominal; only the JOSE header's x5c is
    // replaced, so the SD-JWT signature remains verifiable with the
    // injected leaf certificate's public key (see
    // digital-credential-trust-chain-fault.ts).
    const mutation = await applyDigitalCredentialTrustChainFault({
      issuerSigningJwk: jwks.private,
      profile: activeFaultProfile
    });
    if (!mutation.ok) {
      throw new DigitalCredentialTrustChainFaultApplicationError(
        `Unable to apply the edc-invalid-trust-chain fault to the disability card credential: ${mutation.reason}`
      );
    }

    x5c = mutation.mutation.x5c;
    faultEvidence = mutation.mutation.evidence;
  }

  const credential = await sdjwt.issue(payloadToSign, disclosureFrame, {
    header: {
      kid: jwks.private.kid,
      typ: 'dc+sd-jwt',
      x5c
    }
  });

  return { credential, faultEvidence };
}
