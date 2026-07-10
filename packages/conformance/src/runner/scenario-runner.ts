import { randomUUID } from 'node:crypto';

import { createObservedEvent } from '../events/event-bus.js';
import {
  EventStoreAbortedError,
  EventStoreTimeoutError,
  createInMemoryScenarioEventStore,
  type Disposable,
  type ScenarioEventStore
} from '../events/event-store.js';
import {
  type LocalServiceEndpoints,
  type ProtocolObservedScenarioDefinition,
  type ScenarioStimulus
} from '../scenarios/definitions.js';
import { createProtocolObservedVerdictEngine, type VerdictEngine } from '../verdict/verdict-engine.js';
import { createScenarioPromptModel } from './prompts.js';

import type { ScenarioEventBridgeFactory } from '../events/event-bridge.js';
import type { ScenarioRegistry } from '../scenarios/registry.js';
import type { ScenarioOutcome, ScenarioTimingSummary } from '../verdict/outcome.js';

export interface StartScenarioOptions {
  signal?: AbortSignal;
}

export interface AwaitVerdictOptions {
  signal?: AbortSignal;
}

export interface ScenarioRunner extends AsyncDisposable {
  start(id: string, options?: StartScenarioOptions): Promise<InteractiveScenarioSession>;
  close(): Promise<void>;
}

export interface InteractiveScenarioSession extends AsyncDisposable {
  readonly scenarioId: string;
  readonly correlationId: string;
  readonly definition: ProtocolObservedScenarioDefinition;
  readonly endpoints: LocalServiceEndpoints;
  readonly stimulus: ScenarioStimulus;
  readonly events: ScenarioEventStore;
  readonly abortSignal: AbortSignal;

  showInstructions(): Promise<void>;
  awaitVerdict(options?: AwaitVerdictOptions): Promise<ScenarioOutcome>;
  stop(): Promise<void>;
}

export interface CreateProtocolObservedScenarioRunnerOptions {
  endpoints: LocalServiceEndpoints;
  eventBridgeFactory?: ScenarioEventBridgeFactory;
  eventStoreFactory?: () => ScenarioEventStore;
  registry: ScenarioRegistry;
  verdictEngine?: VerdictEngine;
  write?: (message: string) => void;
}

function defaultWrite(message: string): void {
  process.stdout.write(`${message}\n`);
}

function createCredentialOfferUri(credentialIssuer: string, correlationId: string): string {
  const credentialOffer = {
    credential_issuer: credentialIssuer,
    credential_configuration_ids: ['dc_sd_jwt_PID'],
    grants: {
      authorization_code: {
        issuer_state: correlationId
      }
    }
  };

  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credentialOffer))}`;
}

function resolveScenarioEndpoints(
  definition: ProtocolObservedScenarioDefinition,
  configuredEndpoints: LocalServiceEndpoints
): LocalServiceEndpoints {
  const endpoints: LocalServiceEndpoints = {};

  for (const service of definition.services) {
    const endpoint = configuredEndpoints[service];
    if (!endpoint) throw new Error(`Scenario ${definition.id} requires a ${service} endpoint`);
    endpoints[service] = endpoint;
  }

  return endpoints;
}

function createStimulus(
  definition: ProtocolObservedScenarioDefinition,
  endpoints: LocalServiceEndpoints,
  correlationId: string
): ScenarioStimulus {
  if (definition.stimulus.type === 'credential-offer') {
    const credentialIssuer = endpoints.credentialIssuer;
    if (!credentialIssuer) throw new Error(`Scenario ${definition.id} requires a Credential Issuer endpoint`);
    const uri = createCredentialOfferUri(credentialIssuer, correlationId);
    return { type: 'credential-offer', uri, qrCode: uri };
  }

  if (definition.stimulus.type === 'manual-instruction') {
    return { type: 'manual-instruction', text: definition.stimulus.text };
  }

  throw new Error(`Unsupported stimulus type for scenario ${definition.id}: ${definition.stimulus.type}`);
}

function createTimings(startedAt: string): ScenarioTimingSummary {
  const completedAt = new Date().toISOString();
  return {
    completedAt,
    durationMs: Date.parse(completedAt) - Date.parse(startedAt),
    startedAt
  };
}

function isControlledWaitError(error: unknown): boolean {
  return error instanceof EventStoreTimeoutError || error instanceof EventStoreAbortedError;
}

function writeOutcome(outcome: ScenarioOutcome, write: (message: string) => void): void {
  write('');
  write(`Scenario outcome: ${outcome.verdict}`);
  write(`Reason: ${outcome.reason}`);
  if (outcome.missingEvidence.length > 0) {
    write('Missing evidence:');
    for (const evidence of outcome.missingEvidence) write(`- ${evidence.message}`);
  }
}

function showPrompt(
  definition: ProtocolObservedScenarioDefinition,
  stimulus: ScenarioStimulus,
  endpoints: LocalServiceEndpoints,
  write: (message: string) => void
): void {
  const prompt = createScenarioPromptModel(definition, stimulus);

  write('');
  write(`=== ${prompt.id} - ${prompt.title} ===`);
  write(`Goal: ${prompt.goal}`);
  write(`Expected: ${prompt.expectedBehavior}`);
  write('');
  write('Local endpoints:');
  for (const [name, endpoint] of Object.entries(endpoints)) write(`- ${name}: ${endpoint}`);
  if (prompt.prerequisites.length > 0) {
    write('');
    write('Prerequisites:');
    for (const prerequisite of prompt.prerequisites) write(`- ${prerequisite}`);
  }
  if (prompt.steps.length > 0) {
    write('');
    write('Tester actions:');
    for (const [index, step] of prompt.steps.entries()) write(`${index + 1}. ${step}`);
  }

  if (prompt.stimulus.type === 'credential-offer') {
    write('');
    write('Credential offer deep link:');
    write(prompt.stimulus.uri);
    write('');
    write('QR payload:');
    write(prompt.stimulus.qrCode);
  }

  write('');
  write(`Waiting for event: ${definition.entryEvent}`);
  write(`Timeout: ${Math.ceil(definition.timeouts.testerActionMs / 1000)} seconds`);
}

export function createProtocolObservedScenarioRunner(
  options: CreateProtocolObservedScenarioRunnerOptions
): ScenarioRunner {
  const write = options.write ?? defaultWrite;
  const verdictEngine = options.verdictEngine ?? createProtocolObservedVerdictEngine();
  const activeSessions = new Set<InteractiveScenarioSession>();

  return {
    async start(id, startOptions = {}) {
      if (startOptions.signal?.aborted) throw new Error(`Scenario ${id} start aborted`);

      const definition = options.registry.get(id);
      if (!definition) throw new Error(`Unknown protocol-observed scenario: ${id}`);

      const startedAt = new Date().toISOString();
      const scenarioId = randomUUID();
      const correlationId = randomUUID();
      const abortController = new AbortController();
      const eventStore = options.eventStoreFactory?.() ?? createInMemoryScenarioEventStore();
      const endpoints = resolveScenarioEndpoints(definition, options.endpoints);
      let eventSubscription: Disposable | undefined;
      let stopped = false;
      let outcome: ScenarioOutcome | undefined;
      const stimulus = createStimulus(definition, endpoints, correlationId);
      const eventBridge = await options.eventBridgeFactory?.({
        correlationId,
        definition,
        eventStore,
        scenarioId,
        startedAt
      });

      await eventStore.emit(
        createObservedEvent({
          name: 'credential_offer.generated',
          scenarioId,
          correlationId,
          service: 'collector',
          diagnostic: { stimulusType: stimulus.type }
        })
      );

      const session: InteractiveScenarioSession = {
        scenarioId,
        correlationId,
        definition,
        endpoints,
        stimulus,
        events: eventStore,
        abortSignal: abortController.signal,
        async showInstructions() {
          showPrompt(definition, stimulus, endpoints, write);
          eventSubscription?.dispose();
          eventSubscription = eventStore.subscribe((event) => {
            write(`[event] ${event.name} service=${event.service} scenario=${event.scenarioId ?? 'unmatched'}`);
          });
        },
        async awaitVerdict(awaitOptions = {}) {
          const signal = awaitOptions.signal ?? abortController.signal;

          let entryEvent = eventStore.find((event) => event.name === definition.entryEvent);
          if (!entryEvent) {
            try {
              entryEvent = await eventStore.waitFor(definition.entryEvent, {
                timeoutMs: definition.timeouts.testerActionMs,
                signal,
                inconclusiveMessage: `The wallet did not request ${definition.entryEvent}.`
              });
            } catch (error) {
              if (!isControlledWaitError(error)) throw error;
            }
          }

          if (entryEvent) {
            let previous = entryEvent;
            for (const requiredEvent of definition.requiredEvents ?? []) {
              try {
                previous = await eventStore.waitFor(requiredEvent, {
                  after: previous,
                  timeoutMs: definition.timeouts.protocolStepMs,
                  signal,
                  inconclusiveMessage: `The wallet did not send required event ${requiredEvent}.`
                });
              } catch (error) {
                if (!isControlledWaitError(error)) throw error;
                break;
              }
            }

            if (definition.forbiddenEvents && definition.forbiddenEvents.length > 0) {
              try {
                await eventStore.expectNone(definition.forbiddenEvents, {
                  after: entryEvent,
                  timeoutMs: definition.timeouts.forbiddenObservationMs ?? definition.timeouts.protocolStepMs,
                  signal
                });
              } catch (error) {
                if (!isControlledWaitError(error)) throw error;
              }
            }
          }

          outcome = verdictEngine.evaluate({
            definition,
            events: eventStore.all(),
            artifactValidationResults: [],
            timings: createTimings(startedAt),
            scenarioId
          });
          writeOutcome(outcome, write);
          return outcome;
        },
        async stop() {
          if (stopped) return;
          stopped = true;
          abortController.abort();
          eventSubscription?.dispose();
          eventBridge?.dispose();
          eventStore.close();
          activeSessions.delete(session);
          if (!outcome) write(`Scenario ${definition.id} stopped before verdict.`);
        },
        async [Symbol.asyncDispose]() {
          await this.stop();
        }
      };

      activeSessions.add(session);
      return session;
    },
    async close() {
      await Promise.all([...activeSessions].map((session) => session.stop()));
    },
    async [Symbol.asyncDispose]() {
      await this.close();
    }
  };
}
