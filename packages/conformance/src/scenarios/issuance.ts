import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const issuanceScenarios: ProtocolObservedScenarioDefinition[] = [];

export const issuanceScenarioRegistry = createScenarioRegistry(issuanceScenarios);
