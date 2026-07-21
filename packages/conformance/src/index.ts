export type {
  ClosedConformanceSessionStatus,
  ConformanceCheck,
  ConformanceCheckResult,
  ConformancePhase,
  ConformanceSession,
  ConformanceSessionStatus,
  ConformanceStep
} from './models/types.js';
export type { IConformanceSessionRepository } from './models/types.js';
export { SqliteConformanceSessionRepository } from './repository.js';
export { runConformanceCleanup, startConformanceCleanupJob } from './jobs/cleanup.js';
export {
  buildJsonReporterFromRepository,
  buildJsonReporterFromSession,
  loadSessionForReport,
  type JsonReporterAssertionResult,
  type JsonReporterBuildOptions,
  type JsonReporterBuildResult,
  type JsonReporterResult,
  type JsonReporterTestResult
} from './reporters/json-reporter.js';
export {
  generateRenderedReport,
  renderHtmlReport,
  renderPdfReport,
  type HtmlPdfGeneratorOptions,
  type RenderedReport,
  type ReportFormat
} from './reporters/html-pdf-generator.js';
export { extractIssuerSessionId, extractRpSessionId } from './utils/session-extractor.js';
export type { RequirementDefinition } from './utils/requirement-mapper.js';
export { getRequirements } from './utils/requirement-mapper.js';
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
export { issuanceMatrix } from './matrix/issuance.js';
export { walletInstanceMatrix } from './matrix/wallet-instance.js';
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
export { wp077Scenario } from './scenarios/factories/wp-077.js';
export { wp080Scenario } from './scenarios/factories/wp-080.js';
export type {
  ArtifactExpectation,
  AutomationMode,
  LocalServiceName,
  LocalServiceEndpoints,
  ProtocolObservedPhase,
  ProtocolObservedScenarioDefinition,
  RequiredEventEvidenceExpectation,
  RequiredEventExpectation,
  RequiredEventMatchValue,
  ScenarioInstructions,
  ScenarioStimulus,
  StimulusDefinition,
  TimeoutProfile,
  VerdictRule
} from './scenarios/definitions.js';
export { getRequiredEventName, getRequiredEventNames } from './scenarios/definitions.js';
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
