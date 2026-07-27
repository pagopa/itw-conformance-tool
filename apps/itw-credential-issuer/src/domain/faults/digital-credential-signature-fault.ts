import type { IssuerFaultProfile } from '@itw-conformance-tool/faults';

export type DigitalCredentialSignatureFaultProfile = Extract<IssuerFaultProfile, { type: 'edc-invalid-signature' }>;

export interface ApplyDigitalCredentialSignatureFaultInput {
  /** The already-validated, active WP_062a fault profile. */
  profile: DigitalCredentialSignatureFaultProfile;
  /**
   * The already serialized SD-JWT Combined Format for Issuance. The mutator
   * only touches the issuer-signed compact JWS before the first `~`.
   */
  credential: string;
}

export interface DigitalCredentialSignatureFaultMutationEvidence {
  readonly mutationTarget: 'jws-signature';
  readonly strategy: 'flip-last-signature-byte-low-bit';
  readonly signatureByteLength: number;
}

export interface DigitalCredentialSignatureFaultMutation {
  readonly credential: string;
  readonly evidence: DigitalCredentialSignatureFaultMutationEvidence;
}

export type ApplyDigitalCredentialSignatureFaultResult =
  { ok: true; mutation: DigitalCredentialSignatureFaultMutation } | { ok: false; reason: string };

const BASE64URL_UNPADDED_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Pure, post-serialization mutator for WP_062a. It preserves the protected
 * header, payload, separator placement, and disclosure suffix byte-for-byte,
 * then flips one bit in the decoded signature bytes and re-encodes the
 * signature as valid unpadded base64url.
 */
export function applyDigitalCredentialSignatureFault(
  input: ApplyDigitalCredentialSignatureFaultInput
): ApplyDigitalCredentialSignatureFaultResult {
  const separatorIndex = input.credential.indexOf('~');
  const compactJwt = separatorIndex === -1 ? input.credential : input.credential.slice(0, separatorIndex);
  const disclosureSuffix = separatorIndex === -1 ? '' : input.credential.slice(separatorIndex);
  const segments = compactJwt.split('.');

  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    return {
      ok: false,
      reason: 'Expected the issuer-signed SD-JWT to contain exactly three non-empty compact JWS segments.'
    };
  }

  const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string];
  if (!BASE64URL_UNPADDED_PATTERN.test(encodedSignature)) {
    return {
      ok: false,
      reason: 'Expected the issuer-signed SD-JWT signature segment to be valid unpadded base64url.'
    };
  }

  const signature = Buffer.from(encodedSignature, 'base64url');
  if (signature.length === 0) {
    return {
      ok: false,
      reason: 'Expected the issuer-signed SD-JWT signature segment to decode to at least one byte.'
    };
  }

  const mutatedSignature = Buffer.from(signature);
  mutatedSignature[mutatedSignature.length - 1] ^= 0x01;
  const mutatedEncodedSignature = mutatedSignature.toString('base64url');
  const mutatedCredential = `${encodedHeader}.${encodedPayload}.${mutatedEncodedSignature}${disclosureSuffix}`;

  if (mutatedCredential === input.credential || mutatedEncodedSignature === encodedSignature) {
    return {
      ok: false,
      reason: 'Signature mutation did not change the serialized credential; refusing to emit no-op evidence.'
    };
  }

  return {
    ok: true,
    mutation: {
      credential: mutatedCredential,
      evidence: {
        mutationTarget: 'jws-signature',
        strategy: 'flip-last-signature-byte-low-bit',
        signatureByteLength: signature.length
      }
    }
  };
}
