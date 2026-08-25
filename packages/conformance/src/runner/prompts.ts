import {
  getRequiredEventName,
  type LocalServiceName,
  type ProtocolObservedScenarioDefinition,
  type RequiredEventExpectation,
  type ScenarioStimulus
} from '../scenarios/definitions.js';

import type { ObservedEventName } from '../events/event-types.js';

export interface ScenarioPromptModel {
  details: {
    expectedBehavior: string;
    goal: string;
  };
  endpointLabels: Partial<Record<LocalServiceName, string>>;
  id: string;
  expectedBehavior: string;
  goal: string;
  prerequisites: string[];
  summary: string;
  steps: string[];
  stimulus: ScenarioStimulus;
  title: string;
  waitingFor: string;
}

const endpointLabels: Record<LocalServiceName, string> = {
  credentialIssuer: 'Credential Issuer',
  federation: 'Trust Anchor',
  relyingParty: 'Relying Party',
  walletProvider: 'Wallet Provider'
};

const eventLabels: Partial<Record<ProtocolObservedScenarioDefinition['entryEvent'], string>> = {
  'issuer.entity_configuration.requested': 'the wallet to contact the Credential Issuer',
  'rp.metadata.requested': 'the wallet to contact the Relying Party',
  'trust_anchor.entity_configuration.requested': 'the wallet to contact the Trust Anchor',
  'wallet_provider.entity_configuration.requested': 'the wallet to contact the Wallet Provider'
};

const protocolEventLabels: Partial<Record<ObservedEventName, string>> = {
  'credential_offer.generated': 'Credential Offer generated',
  'presentation_request.generated': 'Presentation request generated',
  'trust_anchor.entity_configuration.requested': 'Wallet contacted the Trust Anchor',
  'wallet_provider.entity_configuration.requested': 'Wallet contacted the Wallet Provider',
  'federation.anchor.requested': 'Wallet contacted the Trust Anchor',
  'federation.fetch.requested': 'Wallet resolved a Trust Anchor statement',
  'issuer.entity_configuration.requested': 'Wallet contacted the Credential Issuer',
  'issuer.metadata.requested': 'Wallet requested Credential Issuer metadata',
  'issuer.par.requested': 'Wallet sent the pushed authorization request',
  'issuer.authorization.requested': 'Wallet opened the authorization step',
  'issuer.token.requested': 'Wallet exchanged the authorization code',
  'issuer.token.failed': 'Wallet token exchange failed as expected',
  'issuer.nonce.requested': 'Wallet requested a fresh nonce',
  'issuer.credential.requested': 'Wallet requested the credential',
  'issuer.credential.issued': 'Credential issued',
  'issuer.credential.deferred': 'Credential issuance deferred',
  'issuer.deferred_credential.requested': 'Wallet requested the deferred credential',
  'issuer.deferred_credential.issued': 'Deferred credential issued',
  'issuer.status_list.requested': 'Wallet checked the Status List',
  'issuer.notification.received': 'Wallet sent an issuance notification',
  'issuer.fault.applied': 'Credential Issuer applied the scenario fault',
  'trust_anchor.fault.applied': 'Trust Anchor applied the scenario fault',
  'rp.metadata.requested': 'Wallet contacted the Relying Party',
  'rp.request_object.requested': 'Wallet retrieved the presentation request object',
  'rp.presentation_response.received': 'Wallet returned the presentation response',
  'rp.redirect.followed': 'Wallet followed the Relying Party redirect',
  'wallet_instance.registration.requested': 'Wallet Instance registration requested',
  'wallet_attestation.requested': 'Wallet Instance Attestation requested',
  'wallet_instance.status_retrieval.requested': 'Wallet Instance status requested',
  'wallet_instance.revocation.requested': 'Wallet Instance revocation requested',
  'jwt.validation.succeeded': 'JWT validation succeeded',
  'jwt.validation.failed': 'JWT validation failed',
  'vp_token.validation.succeeded': 'VP token validation succeeded',
  'vp_token.validation.failed': 'VP token validation failed'
};

export function getProtocolEventLabel(name: ObservedEventName): string {
  return protocolEventLabels[name] ?? 'Protocol event observed';
}

export function getRequiredEventLabel(expectation: RequiredEventExpectation): string {
  if (typeof expectation !== 'string' && expectation.label) return expectation.label;
  return getProtocolEventLabel(getRequiredEventName(expectation));
}

export function createScenarioPromptModel(
  definition: ProtocolObservedScenarioDefinition,
  stimulus: ScenarioStimulus
): ScenarioPromptModel {
  return {
    details: {
      expectedBehavior: definition.instructions.expectedBehavior,
      goal: definition.instructions.goal
    },
    endpointLabels,
    id: definition.id,
    expectedBehavior: definition.instructions.expectedBehavior,
    goal: definition.instructions.goal,
    prerequisites: definition.instructions.prerequisites ?? [],
    summary: definition.instructions.summary ?? definition.instructions.goal,
    steps: definition.instructions.steps ?? [],
    stimulus,
    title: definition.title,
    waitingFor: eventLabels[definition.entryEvent] ?? definition.entryEvent
  };
}
