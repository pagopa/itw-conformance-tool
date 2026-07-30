import type { TimeoutProfile } from '../scenarios/definitions.js';

export type ResolvedTimeoutProfile = Required<TimeoutProfile>;

export function resolveTimeoutProfile(profile: TimeoutProfile): ResolvedTimeoutProfile {
  return {
    forbiddenObservationMs: profile.forbiddenObservationMs ?? profile.protocolStepMs,
    protocolStepMs: profile.protocolStepMs,
    testerActionMs: profile.testerActionMs,
    vitestTestMs: profile.vitestTestMs ?? profile.testerActionMs + profile.protocolStepMs
  };
}
