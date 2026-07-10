import type { ProtocolObservedScenarioDefinition } from '../scenarios/definitions.js';
import type { Disposable, ScenarioEventStore } from './event-store.js';

export interface ScenarioEventBridgeContext {
  correlationId: string;
  definition: ProtocolObservedScenarioDefinition;
  eventStore: ScenarioEventStore;
  scenarioId: string;
  startedAt: string;
}

export type ScenarioEventBridgeFactory = (context: ScenarioEventBridgeContext) => Disposable | Promise<Disposable>;
