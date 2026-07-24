import type { CredentialResponseFaultParameter, IssuerFaultProfile } from '@itw-conformance-tool/faults';
import type { CredentialResponse } from '@pagopa/io-wallet-oid4vci';

export type CredentialResponseFaultProfile = Extract<IssuerFaultProfile, { type: 'edc-missing-required-claims' }>;

export interface ApplyCredentialResponseFaultInput {
  /** The already-validated, active fault profile (parameters to omit). */
  profile: CredentialResponseFaultProfile;
  /** The nominal, already-built SDK Credential Response body. */
  response: CredentialResponse;
  /** Whether the nominal response is the immediate or deferred flow shape. */
  responseKind: 'deferred' | 'immediate';
}

export interface CredentialResponseFaultMutation {
  /** The mutated response body; a new object, never the original reference. */
  readonly body: CredentialResponse;
  /** Safe field names only: never the removed value, a credential, or a token. */
  readonly omittedParameters: readonly CredentialResponseFaultParameter[];
}

export type ApplyCredentialResponseFaultResult =
  { ok: true; mutation: CredentialResponseFaultMutation } | { ok: false; reason: string };

/**
 * Pure mutator for the `edc-missing-required-claims` Credential Response
 * fault. Clones the nominal SDK response and removes only the requested
 * top-level parameters (currently `credentials`), so an immediate issuance
 * response becomes structurally non-conformant without touching the signed
 * Digital Credential itself (see WP_059; WP_060 separately covers the
 * credential's own type/schema validation).
 *
 * Refuses to report success (returns `ok: false`) instead of silently
 * no-op'ing when:
 * - the nominal response is a deferred response (this fault only targets
 *   the immediate-issuance Credential Response shape), or
 * - a requested target parameter is not present in the nominal response,
 *
 * so the caller never emits a false `issuer.fault.applied` event.
 */
export function applyCredentialResponseFault(
  input: ApplyCredentialResponseFaultInput
): ApplyCredentialResponseFaultResult {
  if (input.responseKind !== 'immediate') {
    return {
      ok: false,
      reason: 'The edc-missing-required-claims fault only applies to immediate Credential Responses.'
    };
  }

  const source = input.response as Record<string, unknown>;
  const targets = new Set<string>(input.profile.parameters);
  const omittedParameters: CredentialResponseFaultParameter[] = [];
  const mutatedBody: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(source)) {
    if (targets.has(key)) {
      omittedParameters.push(key as CredentialResponseFaultParameter);
      continue;
    }
    mutatedBody[key] = value;
  }

  const missingTargets = input.profile.parameters.filter((parameter) => !omittedParameters.includes(parameter));
  if (missingTargets.length > 0) {
    return {
      ok: false,
      reason: `Requested omission target(s) not present in the nominal Credential Response: ${missingTargets.join(', ')}`
    };
  }

  return {
    ok: true,
    mutation: {
      body: mutatedBody as CredentialResponse,
      omittedParameters
    }
  };
}
