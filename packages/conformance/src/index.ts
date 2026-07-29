export { extractIssuerSessionId, extractRpSessionId } from './utils/session-extractor.js';
export {
  createInMemoryArtifactStore,
  type ArtifactRef,
  type ArtifactStore,
  type RedactedHttpExchange,
  type RedactedHttpMessage,
  type StoreArtifactOptions,
  type StoredArtifact,
  type StoreJwtOptions
} from './artifacts/artifact-store.js';
export type { ScenarioEventSink } from './events/event-bus.js';
export { createObservedEvent } from './events/event-bus.js';
export type { ScenarioEventBridgeContext, ScenarioEventBridgeFactory } from './events/event-bridge.js';
export {
  EventStoreAbortedError,
  EventStoreTimeoutError,
  ForbiddenObservedEventError,
  createInMemoryScenarioEventStore,
  type Disposable,
  type EventPredicate,
  type NoEventOptions,
  type ScenarioEventStore,
  type WaitOptions
} from './events/event-store.js';
export {
  SqliteScenarioEventRepository,
  createSqliteScenarioEventBridge,
  type CreateSqliteScenarioEventBridgeOptions
} from './events/sqlite-event-repository.js';
export {
  isObservedEventName,
  observedEventNames,
  type BaseObservedEvent,
  type HttpObservedEventName,
  type HttpRequestFailedEvent,
  type HttpRequestReceivedEvent,
  type HttpResponseSentEvent,
  type ObservedEvent,
  type ObservedEventName,
  type ObservedServiceName,
  type ScenarioCorrelation,
  type SemanticObservedEvent,
  type SemanticObservedEventName
} from './events/event-types.js';
export { REDACTED_VALUE, redactHeaders, redactJson, toReportablePayload } from './events/redaction.js';
export type {
  AwaitVerdictOptions,
  CreateProtocolObservedScenarioRunnerOptions,
  InteractiveScenarioSession,
  ScenarioRunner,
  StartScenarioOptions
} from './runner/scenario-runner.js';
export { createProtocolObservedScenarioRunner } from './runner/scenario-runner.js';
export { createScenarioPromptModel, type ScenarioPromptModel } from './runner/prompts.js';
export { resolveTimeoutProfile, type ResolvedTimeoutProfile } from './runner/timeout-profile.js';
export {
  createScenarioRegistry,
  validateProtocolObservedScenarioDefinition,
  type ScenarioRegistry,
  type ScenarioRegistryFilter
} from './scenarios/registry.js';
export { issuanceScenarioRegistry, issuanceScenarios } from './scenarios/issuance.js';
export { presentationScenarioRegistry, presentationScenarios } from './scenarios/presentation.js';
export { walletInstanceScenarioRegistry, walletInstanceScenarios } from './scenarios/wallet-instance.js';
export { wpCiHappyScenario } from './scenarios/factories/wp-ci-happy.js';
export { wp017Scenario } from './scenarios/factories/wp-017.js';
export { wp046aScenario } from './scenarios/factories/wp-046a.js';
export { wp054MissingCodeScenario, wp054Scenarios, type Wp054MissingClaim } from './scenarios/factories/wp-054.js';
export { wp054aInvalidStateScenario } from './scenarios/factories/wp-054a.js';
export { wp054bInvalidIssuerScenario } from './scenarios/factories/wp-054b.js';
export {
  WP_UNSUPPORTED_CREDENTIAL_CONFIGURATION_ID,
  wpUnsupportedCredentialOfferScenario
} from './scenarios/factories/wp-unsupported-credential-offer.js';
export { wp057Scenario } from './scenarios/factories/wp-057.js';
export { wp059Scenario } from './scenarios/factories/wp-059.js';
export { wp060Scenarios, wp060TypeMismatchScenario, type Wp060Variant } from './scenarios/factories/wp-060.js';
export { wp061Scenario } from './scenarios/factories/wp-061.js';
export { wp062aScenario } from './scenarios/factories/wp-062a.js';
export { wp062bScenario } from './scenarios/factories/wp-062b.js';
export { wpNotificationScenario } from './scenarios/factories/wp-notification.js';
export { wpDeferredScenario } from './scenarios/factories/wp-deferred.js';
export type {
  ArtifactExpectation,
  AutomationMode,
  IssuerRuntimeConfigSetup,
  LocalServiceName,
  LocalServiceEndpoints,
  ProtocolObservedPhase,
  ProtocolObservedScenarioDefinition,
  RequiredEventEvidenceExpectation,
  RequiredEventExpectation,
  RequiredEventMatchValue,
  ScenarioInstructions,
  ScenarioSetup,
  ScenarioStimulus,
  StimulusDefinition,
  TimeoutProfile,
  VerdictRule
} from './scenarios/definitions.js';
export { getRequiredEventName, getRequiredEventNames } from './scenarios/definitions.js';
export {
  evaluateUserNeutralEventDescription,
  type UserNeutralEventDescriptionReasonCode,
  type UserNeutralEventDescriptionResult
} from './helpers/notification-policy.js';
export type {
  ActivateIssuerConfigRequest,
  ActivateIssuerFaultRequest,
  DeactivateIssuerConfigRequest,
  DeactivateIssuerFaultRequest,
  IssuerConfigController,
  IssuerFaultController,
  IssuerRuntimeConfig,
  IssuerScenarioController
} from './services/issuer-fault-controller.js';
export type {
  ActivateTrustAnchorFaultRequest,
  DeactivateTrustAnchorFaultRequest,
  TrustAnchorFaultController
} from './services/trust-anchor-fault-controller.js';
export {
  createConformanceInstrumentationPlugin,
  type InstrumentationOptions
} from './services/fastify-instrumentation-plugin.js';
export {
  createProtocolObservedVerdictEngine,
  type VerdictEngine,
  type VerdictInput
} from './verdict/verdict-engine.js';
export type {
  EvidenceItem,
  MissingEvidenceItem,
  ScenarioOutcome,
  ScenarioTimingSummary,
  ScenarioVerdict
} from './verdict/outcome.js';
export type { ArtifactValidationResult } from './verdict/rules.js';
export { assertConformanceOutcome, type AssertConformanceOutcomeOptions } from './vitest/matchers.js';
export { renderPdf } from './report/pdf.js';
export { getLatestSessionId, getSession, listSessions } from './report/session-store.js';
export { renderHtml } from './report/template/index.js';
export type { ReportView } from './report/template/types.js';
