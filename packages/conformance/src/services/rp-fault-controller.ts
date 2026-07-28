import type { RpFaultProfile } from '@itw-conformance-tool/faults';

export interface ActivateRpFaultRequest {
  /** Ownership token for this activation; typically the scenario's initial correlation ID. */
  scenarioId: string;
  /** IT Wallet specification version the scenario expects the Relying Party to resolve. */
  specVersion: string;
  profile: RpFaultProfile;
}

export interface DeactivateRpFaultRequest {
  /** Must match the `scenarioId` used to activate the fault. */
  scenarioId: string;
}

/**
 * Runner-facing control surface for activating/deactivating Relying Party fault
 * profiles. Structurally compatible with `@itw-conformance-tool/ipc`'s
 * `ServiceControlClient`, so the IPC client can be passed directly as an
 * `RpFaultController` without an adapter — the same arrangement the Credential
 * Issuer uses (see `IssuerFaultController`).
 */
export interface RpFaultController {
  activateRpFault(request: ActivateRpFaultRequest): Promise<void>;
  deactivateRpFault(request: DeactivateRpFaultRequest): Promise<void>;
}
