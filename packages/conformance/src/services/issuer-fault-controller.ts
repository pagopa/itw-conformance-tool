import type { IssuerFaultProfile } from '@itw-conformance-tool/faults';

export interface ActivateIssuerFaultRequest {
  /** Ownership token for this activation; typically the scenario's initial correlation ID. */
  scenarioId: string;
  /** IT Wallet specification version the scenario expects the issuer to resolve. */
  specVersion: string;
  profile: IssuerFaultProfile;
}

export interface DeactivateIssuerFaultRequest {
  /** Must match the `scenarioId` used to activate the fault. */
  scenarioId: string;
}

/**
 * Runner-facing control surface for activating/deactivating Credential Issuer
 * fault profiles. Structurally compatible with
 * `@itw-conformance-tool/ipc`'s `ServiceControlClient`, so the IPC client can
 * be passed directly as an `IssuerFaultController` without an adapter.
 */
export interface IssuerFaultController {
  activateIssuerFault(request: ActivateIssuerFaultRequest): Promise<void>;
  deactivateIssuerFault(request: DeactivateIssuerFaultRequest): Promise<void>;
}
