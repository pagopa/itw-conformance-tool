import { IssuerAuth, IssuerSigned } from '@owf/mdoc';

import type { IssuerFaultProfile } from '@itw-conformance-tool/faults';
import type { IssuerAuthEncodedStructure } from '@owf/mdoc';

export type MdocSignatureFaultProfile = Extract<IssuerFaultProfile, { type: 'mdl-invalid-signature' }>;

export interface ApplyMdocSignatureFaultInput {
  /** The already-validated, active WP_062b fault profile. */
  profile: MdocSignatureFaultProfile;
  /** The already serialized OpenID4VCI mdoc credential. */
  credential: string;
}

export interface MdocSignatureFaultMutationEvidence {
  readonly mutationTarget: 'issuerAuth.cose-signature';
  readonly strategy: 'flip-last-signature-byte-low-bit';
  readonly signatureByteLength: number;
}

export interface MdocSignatureFaultMutation {
  readonly credential: string;
  readonly evidence: MdocSignatureFaultMutationEvidence;
}

export type ApplyMdocSignatureFaultResult =
  { ok: true; mutation: MdocSignatureFaultMutation } | { ok: false; reason: string };

const BASE64URL_UNPADDED_PATTERN = /^[A-Za-z0-9_-]+$/;

const isUint8Array = (value: unknown): value is Uint8Array => value instanceof Uint8Array;

const getIssuerAuthEncodedStructure = (issuerSigned: IssuerSigned): IssuerAuthEncodedStructure | undefined => {
  const encodedStructure = issuerSigned.issuerAuth.encodedStructure;

  if (!Array.isArray(encodedStructure) || encodedStructure.length !== 4) {
    return undefined;
  }

  const [protectedHeaders, unprotectedHeaders, payload, signature] = encodedStructure;
  if (
    !isUint8Array(protectedHeaders) ||
    !(unprotectedHeaders instanceof Map) ||
    !(payload === null || isUint8Array(payload)) ||
    !isUint8Array(signature)
  ) {
    return undefined;
  }

  return encodedStructure;
};

/**
 * Pure, post-serialization mutator for WP_062b. It parses the credential as
 * an IssuerSigned mdoc, validates `issuerAuth` as a four-element COSE_Sign1,
 * then flips one deterministic bit in the signature byte string while
 * preserving protected headers, unprotected headers, MSO payload, and
 * namespaces.
 */
export function applyMdocSignatureFault(input: ApplyMdocSignatureFaultInput): ApplyMdocSignatureFaultResult {
  if (!BASE64URL_UNPADDED_PATTERN.test(input.credential)) {
    return {
      ok: false,
      reason: 'Expected the mdoc credential to be valid unpadded base64url.'
    };
  }

  let issuerSigned: IssuerSigned;
  try {
    issuerSigned = IssuerSigned.fromEncodedForOid4Vci(input.credential);
  } catch {
    return {
      ok: false,
      reason: 'Expected the mdoc credential to decode as an IssuerSigned CBOR structure.'
    };
  }

  const issuerAuthEncodedStructure = getIssuerAuthEncodedStructure(issuerSigned);
  if (!issuerAuthEncodedStructure) {
    return {
      ok: false,
      reason: 'Expected issuerAuth to be a four-element COSE_Sign1 structure.'
    };
  }

  const [protectedHeaders, unprotectedHeaders, payload, signature] = issuerAuthEncodedStructure;
  if (signature.length === 0) {
    return {
      ok: false,
      reason: 'Expected issuerAuth COSE_Sign1 signature to contain at least one byte.'
    };
  }

  const mutatedSignature = new Uint8Array(signature);
  mutatedSignature[mutatedSignature.length - 1] ^= 0x01;
  if (mutatedSignature[mutatedSignature.length - 1] === signature[signature.length - 1]) {
    return {
      ok: false,
      reason: 'Signature mutation did not change the COSE_Sign1 signature; refusing to emit no-op evidence.'
    };
  }

  let mutatedCredential: string;
  try {
    const mutatedIssuerAuth = IssuerAuth.fromEncodedStructure([
      protectedHeaders,
      unprotectedHeaders,
      payload,
      mutatedSignature
    ]);
    mutatedCredential = IssuerSigned.create({
      issuerAuth: mutatedIssuerAuth,
      issuerNamespaces: issuerSigned.issuerNamespaces
    }).encodedForOid4Vci;
  } catch {
    return {
      ok: false,
      reason: 'Unable to reconstruct a valid IssuerSigned mdoc after mutating issuerAuth.'
    };
  }

  if (mutatedCredential === input.credential) {
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
        mutationTarget: 'issuerAuth.cose-signature',
        strategy: 'flip-last-signature-byte-low-bit',
        signatureByteLength: signature.length
      }
    }
  };
}
