import type { ArtifactRef } from '../artifacts/artifact-store.js';

export const observedEventNames = [
  'http.request.received',
  'http.response.sent',
  'http.request.failed',
  'http.not_found',
  'preflight.device_probe.received',
  'credential_offer.generated',
  'presentation_request.generated',
  'trust_anchor.entity_configuration.requested',
  'wallet_provider.entity_configuration.requested',
  'federation.anchor.requested',
  'federation.fetch.requested',
  'trust_anchor.fault.applied',
  'issuer.entity_configuration.requested',
  'issuer.fault.applied',
  'issuer.metadata.requested',
  'issuer.par.requested',
  'issuer.authorization.requested',
  'issuer.token.requested',
  'issuer.nonce.requested',
  'issuer.credential.requested',
  'issuer.credential.issued',
  'issuer.credential.deferred',
  'issuer.deferred_credential.requested',
  'issuer.deferred_credential.issued',
  'issuer.notification.received',
  'rp.metadata.requested',
  'rp.request_object.requested',
  'rp.presentation_response.received',
  'rp.redirect.followed',
  'wallet_instance.registration.requested',
  'wallet_attestation.requested',
  'wallet_instance.status_retrieval.requested',
  'wallet_instance.revocation.requested',
  'jwt.validation.succeeded',
  'jwt.validation.failed',
  'vp_token.validation.succeeded',
  'vp_token.validation.failed'
] as const;

export type ObservedEventName = (typeof observedEventNames)[number];

export type HttpObservedEventName =
  'http.request.received' | 'http.response.sent' | 'http.request.failed' | 'http.not_found';

export type SemanticObservedEventName = Exclude<ObservedEventName, HttpObservedEventName>;

export type ObservedServiceName =
  'collector' | 'credential-issuer' | 'federation' | 'relying-party' | 'wallet-provider';

export type RedactedHeaderValue = string | string[] | undefined;

export type RedactedHeaders = Record<string, RedactedHeaderValue>;

export interface ScenarioCorrelation {
  correlationId: string;
}

export interface BaseObservedEvent {
  id: string;
  name: ObservedEventName;
  correlationId: string | null;
  service: ObservedServiceName;
  timestamp: string;
  monotonicMs: number;
  requestId?: string;
  artifactRefs?: ArtifactRef[];
  diagnostic?: Record<string, unknown>;
}

export interface HttpRequestDetails {
  method: string;
  url: string;
  path: string | null;
  headers: RedactedHeaders;
}

export interface HttpResponseDetails {
  statusCode: number;
  contentType: string;
  durationMs?: number;
}

export interface ObservedErrorDetails {
  message: string;
  name: string;
}

export interface HttpRequestReceivedEvent extends BaseObservedEvent {
  name: 'http.request.received' | 'http.not_found';
  http: HttpRequestDetails;
}

export interface HttpResponseSentEvent extends BaseObservedEvent {
  name: 'http.response.sent';
  http: HttpResponseDetails;
}

export interface HttpRequestFailedEvent extends BaseObservedEvent {
  name: 'http.request.failed';
  error: ObservedErrorDetails;
}

export interface SemanticObservedEvent extends BaseObservedEvent {
  name: SemanticObservedEventName;
  validation?: Record<string, unknown>;
}

export type ObservedEvent =
  HttpRequestFailedEvent | HttpRequestReceivedEvent | HttpResponseSentEvent | SemanticObservedEvent;

export function isObservedEventName(value: string): value is ObservedEventName {
  return observedEventNames.includes(value as ObservedEventName);
}
