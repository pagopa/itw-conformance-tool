import { wp077Scenario } from './factories/wp-077.js';
import { wp080Scenario } from './factories/wp-080.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const presentationScenarios: ProtocolObservedScenarioDefinition[] = [wp077Scenario, wp080Scenario];

export const presentationScenarioRegistry = createScenarioRegistry(presentationScenarios);
