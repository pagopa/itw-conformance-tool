import { wp046Scenario } from './factories/wp-046.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const issuanceScenarios: ProtocolObservedScenarioDefinition[] = [wp046Scenario];

export const issuanceScenarioRegistry = createScenarioRegistry(issuanceScenarios);
