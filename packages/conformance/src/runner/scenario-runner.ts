import { randomUUID } from 'node:crypto';

import { sha256HashArtifact } from '@itw-conformance-tool/utils';
import chalk from 'chalk';
import open from 'open';

import { createObservedEvent } from '../events/event-bus.js';
import {
  EventStoreAbortedError,
  EventStoreTimeoutError,
  ForbiddenObservedEventError,
  createInMemoryScenarioEventStore,
  type Disposable,
  type ScenarioEventStore
} from '../events/event-store.js';
import { NOMINAL_CREDENTIAL_CONFIGURATION_ID, createCredentialOfferUri } from '../helpers/issuance.js';
import { createPresentationRequestUri, extractPresentationCorrelationId } from '../helpers/presentation.js';
import { getForbiddenEventNames, getRequiredEventName, hasVerdictRule } from '../scenarios/definitions.js';
import {
  type LocalServiceEndpoints,
  type ProtocolObservedScenarioDefinition,
  type ScenarioStimulus,
  type StimulusDelivery
} from '../scenarios/definitions.js';
import { type IssuerScenarioController } from '../services/issuer-fault-controller.js';
import { type RpFaultController } from '../services/rp-fault-controller.js';
import { type TrustAnchorFaultController } from '../services/trust-anchor-fault-controller.js';
import { createProtocolObservedVerdictEngine, type VerdictEngine } from '../verdict/verdict-engine.js';
import { copyTextToClipboard } from './clipboard.js';
import { createPresentationRequestPageUrl, renderTerminalQrCode, targetsLoopbackHost } from './engagement.js';
import { createScenarioPromptModel } from './prompts.js';

import type { ScenarioEventBridgeFactory } from '../events/event-bridge.js';
import type { ScenarioRegistry } from '../scenarios/registry.js';
import type { ScenarioOutcome, ScenarioTimingSummary } from '../verdict/outcome.js';
import type { IssuerFaultProfile } from '@itw-conformance-tool/faults';

/** Default IT Wallet specification version reported at issuer fault activation when not overridden. */
const DEFAULT_ISSUER_FAULT_SPEC_VERSION = '1.4';

/**
 * Default IT Wallet specification version reported at Relying Party fault
 * activation when not overridden. The local Relying Party is pinned to `1.4`
 * (see `apps/itw-relying-party/src/plugins/sdk.ts`).
 */
const DEFAULT_RP_FAULT_SPEC_VERSION = '1.4';

export interface StartScenarioOptions {
  signal?: AbortSignal;
}

export interface AwaitVerdictOptions {
  signal?: AbortSignal;
}

export type BrowserOpener = (url: string) => Promise<void>;

export interface ScenarioRunner extends AsyncDisposable {
  start(id: string, options?: StartScenarioOptions): Promise<InteractiveScenarioSession>;
  close(): Promise<void>;
}

export interface InteractiveScenarioSession extends AsyncDisposable {
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
  /** Required to run any scenario that declares `setup.issuerFault` or `setup.issuerConfig`. */
  issuerFaultController?: IssuerScenarioController;
  /** IT Wallet specification version reported when activating an issuer fault. Defaults to '1.4'. */
  issuerFaultSpecVersion?: string;
  /** Required to run any scenario that declares `setup.rpFault`. */
  rpFaultController?: RpFaultController;
  /** IT Wallet specification version reported when activating a Relying Party fault. Defaults to '1.4'. */
  rpFaultSpecVersion?: string;
  /** Required to run any scenario that declares `setup.trustAnchorFault`. */
  trustAnchorFaultController?: TrustAnchorFaultController;
  /** IT Wallet specification version reported when activating a Trust Anchor fault. Defaults to '1.4'. */
  trustAnchorFaultSpecVersion?: string;
  /** Opens local browser pages for interactive scenario stimuli. Defaults to the system browser opener. */
  browserOpener?: BrowserOpener;
  /**
   * Base URI presentation engagements are built on: the Wallet Solution's
   * custom scheme or claimed universal link. Omitted, the Relying Party keeps
   * its own default.
   */
  walletAuthBaseUri?: string;
}

function defaultWrite(message: string): void {
  // eslint-disable-next-line no-console
  console.log(message);
}

async function defaultBrowserOpener(url: string): Promise<void> {
  await open(url);
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

interface CreatedStimulus {
  correlationId: string;
  credentialConfigurationId?: string;
  credentialConfigurationIds?: string[];
  stimulus: ScenarioStimulus;
}

async function createStimulus(
  definition: ProtocolObservedScenarioDefinition,
  endpoints: LocalServiceEndpoints,
  correlationId: string,
  issuerFaultProfile: IssuerFaultProfile | undefined,
  walletAuthBaseUri: string | undefined
): Promise<CreatedStimulus> {
  if (definition.stimulus.type === 'credential-offer') {
    const credentialIssuer = endpoints.credentialIssuer;
    if (!credentialIssuer) throw new Error(`Scenario ${definition.id} requires a Credential Issuer endpoint`);
    if (definition.stimulus.credentialConfigurationIds?.length === 0) {
      throw new Error(`Scenario ${definition.id} declares an empty credentialConfigurationIds list`);
    }
    const selectedCredentialConfigurationIds = definition.stimulus.credentialConfigurationIds
      ? [...definition.stimulus.credentialConfigurationIds]
      : [definition.stimulus.credentialConfigurationId ?? NOMINAL_CREDENTIAL_CONFIGURATION_ID];
    const uri = createCredentialOfferUri(
      credentialIssuer,
      correlationId,
      issuerFaultProfile,
      selectedCredentialConfigurationIds
    );
    const effectiveCredentialConfigurationIds =
      issuerFaultProfile?.type === 'unsupported-credential-offer'
        ? [issuerFaultProfile.credentialConfigurationId]
        : selectedCredentialConfigurationIds;
    return {
      correlationId,
      credentialConfigurationId: effectiveCredentialConfigurationIds[0],
      credentialConfigurationIds: effectiveCredentialConfigurationIds,
      stimulus: { type: 'credential-offer', uri, qrCode: uri }
    };
  }

  if (definition.stimulus.type === 'manual-instruction') {
    return { correlationId, stimulus: { type: 'manual-instruction', text: definition.stimulus.text } };
  }

  if (definition.stimulus.type === 'presentation-request') {
    const relyingParty = endpoints.relyingParty;
    if (!relyingParty) throw new Error(`Scenario ${definition.id} requires a Relying Party endpoint`);
    // A deep-link engagement drives a same-device flow (the wallet redirects the
    // user-agent back to the RP), whereas a QR engagement drives a cross-device
    // flow (the verifier polls status). This decides whether a redirect_uri
    // follow is expected.
    const flowType = definition.stimulus.delivery.includes('deep-link') ? 'same-device' : 'cross-device';
    const uri = await createPresentationRequestUri(relyingParty, {
      clientIdPrefix: definition.stimulus.clientIdPrefix,
      flowType,
      requestUriMethod: definition.stimulus.requestUriMethod,
      walletAuthBaseUri
    });
    return {
      correlationId: extractPresentationCorrelationId(uri),
      stimulus: { type: 'presentation-request', uri, qrCode: uri }
    };
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

async function copyQrPayloadToClipboard(stimulus: ScenarioStimulus, write: (message: string) => void): Promise<void> {
  if (stimulus.type !== 'credential-offer' && stimulus.type !== 'presentation-request') return;

  if (await copyTextToClipboard(stimulus.qrCode)) {
    write(chalk.green('QR payload copied to your clipboard.'));
    write('');
  } else {
    write(chalk.dim('Could not access the system clipboard; copy the QR payload shown above manually.'));
  }
}

function showPrompt(
  definition: ProtocolObservedScenarioDefinition,
  stimulus: ScenarioStimulus,
  endpoints: LocalServiceEndpoints,
  write: (message: string) => void,
  terminalQrCode?: string
): void {
  const prompt = createScenarioPromptModel(definition, stimulus);
  const testerActionTimeoutSeconds = Math.ceil(definition.timeouts.testerActionMs / 1000);

  write('');
  write(chalk.bold.cyan(`╭─ ${prompt.id} · ${prompt.title}`));
  write(`${chalk.bold('Goal')}      ${prompt.goal}`);
  write(`${chalk.bold('Expected')}  ${prompt.expectedBehavior}`);
  write(chalk.bold.cyan('╰────────────────────────────────────────────────────────────'));
  write('');
  write(chalk.bold.blue('Local endpoints'));
  for (const [name, endpoint] of Object.entries(endpoints)) {
    write(`  ${chalk.gray('•')} ${chalk.magenta(name)} ${chalk.gray('→')} ${chalk.cyan(endpoint)}`);
  }
  if (prompt.prerequisites.length > 0) {
    write('');
    write(chalk.bold.blue('Prerequisites'));
    for (const prerequisite of prompt.prerequisites) write(`  ${chalk.gray('•')} ${prerequisite}`);
  }
  if (prompt.steps.length > 0) {
    write('');
    write(chalk.bold.blue('Tester actions'));
    for (const [index, step] of prompt.steps.entries()) write(`  ${chalk.yellow(`${index + 1}.`)} ${step}`);
  }

  if (prompt.stimulus.type === 'credential-offer') {
    write('');
    write(chalk.bold.blue('Credential offer deep link'));
    write(chalk.cyan(prompt.stimulus.uri));
    write('');
    write(chalk.bold.blue('QR payload'));
    write(chalk.dim(prompt.stimulus.qrCode));
  }

  if (prompt.stimulus.type === 'presentation-request') {
    write('');
    write(chalk.bold.blue('Presentation engagement URI'));
    write(chalk.cyan(prompt.stimulus.uri));
    write(chalk.dim(decodeURIComponent(prompt.stimulus.qrCode)));
    if (terminalQrCode) {
      write('');
      write(terminalQrCode);
    }
  }

  write('');
  write(`${chalk.bold('Waiting for event')} ${chalk.green(definition.entryEvent)}`);
  write(`${chalk.bold('Timeout')} ${chalk.yellow(`${testerActionTimeoutSeconds} seconds`)}`);
}

function createCredentialOfferPageUrl(credentialIssuer: string, credentialOfferUri: string): string {
  const pageUrl = new URL('/credential-offer', credentialIssuer);
  pageUrl.searchParams.set('credential_offer_uri', credentialOfferUri);

  return pageUrl.toString();
}

async function openCredentialOfferPage(
  stimulus: ScenarioStimulus,
  endpoints: LocalServiceEndpoints,
  browserOpener: BrowserOpener,
  write: (message: string) => void
): Promise<void> {
  if (stimulus.type !== 'credential-offer') return;

  const credentialIssuer = endpoints.credentialIssuer;
  if (!credentialIssuer) return;

  const pageUrl = createCredentialOfferPageUrl(credentialIssuer, stimulus.uri);

  try {
    await browserOpener(pageUrl);
  } catch (error) {
    write(chalk.yellow('Could not open the credential offer page in the default browser.'));
    write(chalk.dim(`Open it manually if needed: ${pageUrl}`));
    write(chalk.dim(error instanceof Error ? error.message : String(error)));
    write('');
  }
}

/** Opens the Relying Party page that renders the engagement as a QR code, the
 * cross-device counterpart of the Credential Offer page.
 */
async function openPresentationRequestPage(
  stimulus: ScenarioStimulus,
  endpoints: LocalServiceEndpoints,
  browserOpener: BrowserOpener,
  write: (message: string) => void
): Promise<void> {
  if (stimulus.type !== 'presentation-request') return;

  const relyingParty = endpoints.relyingParty;
  if (!relyingParty) return;

  const pageUrl = createPresentationRequestPageUrl(relyingParty, stimulus.uri);

  try {
    await browserOpener(pageUrl);
  } catch (error) {
    write(chalk.yellow('Could not open the presentation request page in the default browser.'));
    write(chalk.dim(`Open it manually if needed: ${pageUrl}`));
    write(chalk.dim(error instanceof Error ? error.message : String(error)));
    write('');
  }
}

/** Warns when a cross-device QR engagement points at a loopback host, which the
 * scanning device resolves to itself instead of to the local services.
 */
function warnAboutUnreachableEngagementHost(stimulus: ScenarioStimulus, write: (message: string) => void): void {
  if (stimulus.type !== 'presentation-request') return;
  if (!targetsLoopbackHost(stimulus.uri)) return;

  write(
    chalk.yellow(
      'This engagement points at a loopback host, which a scanning device resolves to itself. For a cross-device flow, set the local service URLs in config.ini to this machine’s LAN address.'
    )
  );
}

export function createProtocolObservedScenarioRunner(
  options: CreateProtocolObservedScenarioRunnerOptions
): ScenarioRunner {
  const write = options.write ?? defaultWrite;
  const browserOpener = options.browserOpener ?? defaultBrowserOpener;
  const verdictEngine = options.verdictEngine ?? createProtocolObservedVerdictEngine();
  const activeSessions = new Set<InteractiveScenarioSession>();

  return {
    async start(id, startOptions = {}) {
      if (startOptions.signal?.aborted) throw new Error(`Scenario ${id} start aborted`);

      const definition = options.registry.get(id);
      if (!definition) throw new Error(`Unknown protocol-observed scenario: ${id}`);

      const startedAt = new Date().toISOString();
      const initialCorrelationId = randomUUID();
      const abortController = new AbortController();
      const eventStore = options.eventStoreFactory?.() ?? createInMemoryScenarioEventStore();
      const endpoints = resolveScenarioEndpoints(definition, options.endpoints);
      let eventSubscription: Disposable | undefined;
      let stopped = false;
      let outcome: ScenarioOutcome | undefined;
      let credentialOfferPageOpened = false;
      let presentationRequestPageOpened = false;

      const issuerFaultProfile = definition.setup?.issuerFault;
      const issuerConfig = definition.setup?.issuerConfig;
      const rpFaultProfile = definition.setup?.rpFault;
      let issuerConfigActive = false;
      let issuerFaultActive = false;
      let rpFaultActive = false;
      const trustAnchorFaultProfile = definition.setup?.trustAnchorFault;
      let trustAnchorFaultActive = false;

      const deactivateIssuerConfigIfActive = async (): Promise<void> => {
        if (!issuerConfigActive) return;
        issuerConfigActive = false;
        await options.issuerFaultController?.deactivateIssuerConfig({ scenarioId: initialCorrelationId });
      };

      const deactivateIssuerFaultIfActive = async (): Promise<void> => {
        if (!issuerFaultActive) return;
        issuerFaultActive = false;
        await options.issuerFaultController?.deactivateIssuerFault({ scenarioId: initialCorrelationId });
      };

      const deactivateRpFaultIfActive = async (): Promise<void> => {
        if (!rpFaultActive) return;
        rpFaultActive = false;
        await options.rpFaultController?.deactivateRpFault({ scenarioId: initialCorrelationId });
      };

      const deactivateTrustAnchorFaultIfActive = async (): Promise<void> => {
        if (!trustAnchorFaultActive) return;
        trustAnchorFaultActive = false;
        await options.trustAnchorFaultController?.deactivateTrustAnchorFault({ scenarioId: initialCorrelationId });
      };

      try {
        if (issuerFaultProfile) {
          if (!options.issuerFaultController) {
            throw new Error(
              `Scenario ${definition.id} declares setup.issuerFault, but no issuerFaultController is configured`
            );
          }

          // Await activation before creating/showing the stimulus, so the
          // Credential Issuer never serves a nominal response for this run.
          await options.issuerFaultController.activateIssuerFault({
            scenarioId: initialCorrelationId,
            specVersion: options.issuerFaultSpecVersion ?? DEFAULT_ISSUER_FAULT_SPEC_VERSION,
            profile: issuerFaultProfile
          });
          issuerFaultActive = true;
        }

        if (rpFaultProfile) {
          if (!options.rpFaultController) {
            throw new Error(`Scenario ${definition.id} declares setup.rpFault, but no rpFaultController is configured`);
          }

          // Await activation before creating the presentation request, so the
          // Relying Party never serves a nominal artifact for this run.
          await options.rpFaultController.activateRpFault({
            scenarioId: initialCorrelationId,
            specVersion: options.rpFaultSpecVersion ?? DEFAULT_RP_FAULT_SPEC_VERSION,
            profile: rpFaultProfile
          });
          rpFaultActive = true;
        }

        if (trustAnchorFaultProfile) {
          if (!options.trustAnchorFaultController) {
            throw new Error(
              `Scenario ${definition.id} declares setup.trustAnchorFault, but no trustAnchorFaultController is configured`
            );
          }

          // Await activation before creating/showing the stimulus, so the
          // Trust Anchor never serves a nominal Entity Configuration for this run.
          await options.trustAnchorFaultController.activateTrustAnchorFault({
            scenarioId: initialCorrelationId,
            specVersion: options.trustAnchorFaultSpecVersion ?? DEFAULT_ISSUER_FAULT_SPEC_VERSION,
            profile: trustAnchorFaultProfile
          });
          trustAnchorFaultActive = true;
        }

        if (issuerConfig) {
          if (!options.issuerFaultController) {
            throw new Error(
              `Scenario ${definition.id} declares setup.issuerConfig, but no issuerFaultController is configured`
            );
          }

          // Await activation before creating/showing the stimulus, so the
          // Credential Issuer evaluates this run with the scenario override.
          await options.issuerFaultController.activateIssuerConfig({
            scenarioId: initialCorrelationId,
            config: issuerConfig
          });
          issuerConfigActive = true;
        }

        const { correlationId, credentialConfigurationId, credentialConfigurationIds, stimulus } = await createStimulus(
          definition,
          endpoints,
          initialCorrelationId,
          issuerFaultProfile,
          options.walletAuthBaseUri
        );
        const eventBridge = await options.eventBridgeFactory?.({
          correlationId,
          definition,
          endpoints,
          eventStore,
          startedAt
        });

        // Safe (non-sensitive) local evidence that the unsupported-credential-offer
        // fault was applied to this stimulus: the fault type, the injected test
        // identifier, and a hash of the shown URI. Never the URI/payload itself,
        // and never a token or credential.
        let appliedIssuerFaultDiagnostic: Record<string, unknown> = {};
        if (stimulus.type === 'credential-offer' && issuerFaultProfile?.type === 'unsupported-credential-offer') {
          appliedIssuerFaultDiagnostic = {
            faultProfileType: issuerFaultProfile.type,
            artifactHash: sha256HashArtifact(stimulus.uri),
            outcome: 'applied'
          };
        }

        await eventStore.emit(
          createObservedEvent({
            name:
              stimulus.type === 'presentation-request'
                ? 'presentation_request.generated'
                : 'credential_offer.generated',
            correlationId,
            service: 'collector',
            diagnostic: {
              stimulusType: stimulus.type,
              credentialConfigurationId,
              credentialConfigurationIds,
              ...appliedIssuerFaultDiagnostic
            }
          })
        );

        const session: InteractiveScenarioSession = {
          correlationId,
          definition,
          endpoints,
          stimulus,
          events: eventStore,
          abortSignal: abortController.signal,
          async showInstructions() {
            // A scenario declaring a QR delivery gets the engagement rendered as
            // a scannable code; a deep-link one is transferred to the wallet's
            // device by the tester, from the clipboard.
            const delivery: readonly StimulusDelivery[] =
              definition.stimulus.type === 'presentation-request' ? definition.stimulus.delivery : [];
            const showQrCode = delivery.includes('qr');

            const terminalQrCode =
              showQrCode && stimulus.type === 'presentation-request'
                ? await renderTerminalQrCode(stimulus.uri)
                : undefined;

            showPrompt(definition, stimulus, endpoints, write, terminalQrCode);
            await copyQrPayloadToClipboard(stimulus, write);
            if (showQrCode) {
              warnAboutUnreachableEngagementHost(stimulus, write);
              if (!presentationRequestPageOpened) {
                presentationRequestPageOpened = true;
                await openPresentationRequestPage(stimulus, endpoints, browserOpener, write);
              }
            }
            if (!credentialOfferPageOpened) {
              credentialOfferPageOpened = true;
              await openCredentialOfferPage(stimulus, endpoints, browserOpener, write);
            }
            eventSubscription?.dispose();
            eventSubscription = eventStore.subscribe((event) => {
              write(`[event] ${event.name} service=${event.service} correlation=${event.correlationId ?? 'unmatched'}`);
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
              const enforceOrder = hasVerdictRule(definition, 'required-events-in-order');
              let previous = entryEvent;
              for (const requiredEvent of definition.requiredEvents ?? []) {
                const requiredEventName = getRequiredEventName(requiredEvent);
                if (requiredEventName === entryEvent.name) continue;

                try {
                  const observed = await eventStore.waitFor(requiredEventName, {
                    after: enforceOrder ? previous : entryEvent,
                    timeoutMs: definition.timeouts.protocolStepMs,
                    signal,
                    inconclusiveMessage: `The wallet did not send required event ${requiredEventName}.`
                  });
                  if (enforceOrder) previous = observed;
                } catch (error) {
                  if (!isControlledWaitError(error)) throw error;
                  break;
                }
              }

              const forbiddenEventNames = getForbiddenEventNames(definition.forbiddenEvents);
              if (forbiddenEventNames.length > 0) {
                try {
                  await eventStore.expectNone(forbiddenEventNames, {
                    after: entryEvent,
                    timeoutMs: definition.timeouts.forbiddenObservationMs ?? definition.timeouts.protocolStepMs,
                    signal
                  });
                } catch (error) {
                  // Observing a forbidden event is a scenario outcome, not a
                  // runner failure: stop waiting and let the verdict engine
                  // report it as a FAIL, with the event as evidence, from the
                  // same event store.
                  if (!isControlledWaitError(error) && !(error instanceof ForbiddenObservedEventError)) throw error;
                }
              }
            }

            outcome = verdictEngine.evaluate({
              definition,
              events: eventStore.all(),
              artifactValidationResults: [],
              timings: createTimings(startedAt)
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
            // Deactivate last so any deactivation failure still surfaces to the caller.
            await deactivateIssuerConfigIfActive();
            await deactivateIssuerFaultIfActive();
            await deactivateRpFaultIfActive();
            await deactivateTrustAnchorFaultIfActive();
          },
          async [Symbol.asyncDispose]() {
            await this.stop();
          }
        };

        activeSessions.add(session);
        return session;
      } catch (error) {
        // Best-effort cleanup on any startup failure (including a missing
        // controller, activation failure, or a later error before the
        // session object exists) so a fault is never left dangling.
        await deactivateIssuerConfigIfActive().catch(() => undefined);
        await deactivateIssuerFaultIfActive().catch(() => undefined);
        await deactivateRpFaultIfActive().catch(() => undefined);
        await deactivateTrustAnchorFaultIfActive().catch(() => undefined);
        throw error;
      }
    },
    async close() {
      await Promise.all([...activeSessions].map((session) => session.stop()));
    },
    async [Symbol.asyncDispose]() {
      await this.close();
    }
  };
}
