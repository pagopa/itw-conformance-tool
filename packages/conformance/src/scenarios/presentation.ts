import { wp077Scenario } from './factories/wp-077.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const presentationScenarios: ProtocolObservedScenarioDefinition[] = [wp077Scenario];

export const presentationScenarioRegistry = createScenarioRegistry(presentationScenarios);
