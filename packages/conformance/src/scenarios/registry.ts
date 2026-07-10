import { isObservedEventName } from '../events/event-types.js';

import type { ObservedEventName } from '../events/event-types.js';
import type { ProtocolObservedPhase, ProtocolObservedScenarioDefinition } from './definitions.js';

export interface ScenarioRegistryFilter {
  automationMode?: ProtocolObservedScenarioDefinition['automationMode'];
  phase?: ProtocolObservedPhase;
}

export interface ScenarioRegistry {
  get(id: string): ProtocolObservedScenarioDefinition | undefined;
  list(filter?: ScenarioRegistryFilter): ProtocolObservedScenarioDefinition[];
}

function assertCatalogEvent(name: ObservedEventName, field: string, scenarioId: string): void {
  if (!isObservedEventName(name)) {
    throw new Error(`Unknown observed event in ${scenarioId}.${field}: ${name}`);
  }
}

export function validateProtocolObservedScenarioDefinition(definition: ProtocolObservedScenarioDefinition): void {
  assertCatalogEvent(definition.entryEvent, 'entryEvent', definition.id);

  for (const [index, event] of (definition.requiredEvents ?? []).entries()) {
    assertCatalogEvent(event, `requiredEvents[${index}]`, definition.id);
  }

  for (const [index, event] of (definition.forbiddenEvents ?? []).entries()) {
    assertCatalogEvent(event, `forbiddenEvents[${index}]`, definition.id);
  }

  for (const [index, expectation] of (definition.artifactExpectations ?? []).entries()) {
    assertCatalogEvent(expectation.event, `artifactExpectations[${index}].event`, definition.id);
  }

  const required = new Set(definition.requiredEvents ?? []);
  const duplicated = (definition.forbiddenEvents ?? []).find((event) => required.has(event));
  if (duplicated) {
    throw new Error(`Scenario ${definition.id} declares ${duplicated} as both required and forbidden`);
  }

  if (definition.timeouts.protocolStepMs <= 0 || definition.timeouts.testerActionMs <= 0) {
    throw new Error(`Scenario ${definition.id} declares invalid timeouts`);
  }
}

export function createScenarioRegistry(definitions: ProtocolObservedScenarioDefinition[]): ScenarioRegistry {
  const byId = new Map<string, ProtocolObservedScenarioDefinition>();

  for (const definition of definitions) {
    if (byId.has(definition.id)) throw new Error(`Duplicate scenario id: ${definition.id}`);
    validateProtocolObservedScenarioDefinition(definition);
    byId.set(definition.id, definition);
  }

  return {
    get: (id) => byId.get(id),
    list(filter = {}) {
      return [...byId.values()].filter((definition) => {
        if (filter.phase && definition.phase !== filter.phase) return false;
        if (filter.automationMode && definition.automationMode !== filter.automationMode) return false;
        return true;
      });
    }
  };
}
