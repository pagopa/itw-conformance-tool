import type { TrustAnchorFaultProfile } from '@itw-conformance-tool/faults';

export interface ActivateTrustAnchorFaultRequest {
  /** Ownership token for this activation; typically the scenario's initial correlation ID. */
  scenarioId: string;
  /** IT Wallet specification version the scenario expects the Trust Anchor to resolve. */
  specVersion: string;
  profile: TrustAnchorFaultProfile;
}

export interface DeactivateTrustAnchorFaultRequest {
  /** Must match the `scenarioId` used to activate the fault. */
  scenarioId: string;
}

/**
 * Runner-facing control surface for activating/deactivating Trust Anchor
 * fault profiles. Structurally compatible with `@itw-conformance-tool/ipc`'s
 * `ServiceControlClient`.
 */
export interface TrustAnchorFaultController {
  activateTrustAnchorFault(request: ActivateTrustAnchorFaultRequest): Promise<void>;
  deactivateTrustAnchorFault(request: DeactivateTrustAnchorFaultRequest): Promise<void>;
}
