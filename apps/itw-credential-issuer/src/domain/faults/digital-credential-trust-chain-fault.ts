import { createHash } from 'node:crypto';

import { convertPemToBase64Der, createSelfSignedCertificateFromJwk } from '@itw-conformance-tool/crypto';

import type { IssuerFaultProfile } from '@itw-conformance-tool/faults';
import type { JWK } from 'jose';

export type DigitalCredentialTrustChainFaultProfile = Extract<IssuerFaultProfile, { type: 'edc-invalid-trust-chain' }>;

export interface ApplyDigitalCredentialTrustChainFaultInput {
  /** The already-validated, active WP_061 fault profile. */
  profile: DigitalCredentialTrustChainFaultProfile;
  /**
   * The issuer's private signing JWK (the same key that signs the SD-JWT
   * VC), used to derive a self-signed leaf certificate that shares its
   * public key. Never included in the returned evidence.
   */
  issuerSigningJwk: JWK;
}

/**
 * Safe, non-sensitive diagnostic evidence describing the injected `x5c`:
 * the mutated header field, the mutation strategy, the resulting chain
 * length, and a SHA-256 thumbprint of the generated certificate. Never
 * includes the certificate PEM/DER, the private JWK, or any credential
 * material.
 */
export interface DigitalCredentialTrustChainFaultMutationEvidence {
  readonly mutationTarget: 'x5c';
  readonly strategy: 'self-signed-untrusted-leaf';
  readonly chainLength: number;
  readonly certificateThumbprintSha256: string;
}

export interface DigitalCredentialTrustChainFaultMutation {
  /** Base64 DER-encoded `x5c` chain: a single self-signed, untrusted leaf certificate. */
  readonly x5c: [string];
  readonly evidence: DigitalCredentialTrustChainFaultMutationEvidence;
}

export type ApplyDigitalCredentialTrustChainFaultResult =
  { ok: true; mutation: DigitalCredentialTrustChainFaultMutation } | { ok: false; reason: string };

/**
 * Pure-effect, pre-signature mutator for the WP_061 `edc-invalid-trust-chain`
 * fault. Must be invoked while building the JOSE header passed to
 * `sdjwt.issue`, so the resulting SD-JWT VC remains validly signed (the
 * injected leaf certificate shares its public key with the issuer signing
 * JWK) while its `x5c` cannot be validated against the configured Trust
 * Anchor -- isolating this from `digital-credential-claims-invalid` (WP_060,
 * a payload defect) and `edc-invalid-signature` (WP_062a, a signature
 * defect).
 *
 * Returns an explicit failure (`ok: false`), and must not be treated as
 * producing mutation evidence, when certificate generation or encoding
 * fails for any reason (e.g. an incompatible signing JWK).
 */
export async function applyDigitalCredentialTrustChainFault(
  input: ApplyDigitalCredentialTrustChainFaultInput
): Promise<ApplyDigitalCredentialTrustChainFaultResult> {
  try {
    const certificatePem = await createSelfSignedCertificateFromJwk(input.issuerSigningJwk);
    const certificateDer = convertPemToBase64Der(certificatePem);
    const certificateThumbprintSha256 = createHash('sha256')
      .update(Buffer.from(certificateDer, 'base64'))
      .digest('hex');

    return {
      ok: true,
      mutation: {
        x5c: [certificateDer],
        evidence: {
          mutationTarget: 'x5c',
          strategy: 'self-signed-untrusted-leaf',
          chainLength: 1,
          certificateThumbprintSha256
        }
      }
    };
  } catch (error) {
    return {
      ok: false,
      reason: `Unable to generate the untrusted self-signed trust-chain certificate: ${
        error instanceof Error ? error.message : String(error)
      }`
    };
  }
}
