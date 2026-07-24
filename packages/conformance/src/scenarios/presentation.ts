import { wpRpHappyScenario } from './factories/wp-rp-happy.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const presentationScenarios: ProtocolObservedScenarioDefinition[] = [wpRpHappyScenario];

export const presentationScenarioRegistry = createScenarioRegistry(presentationScenarios);
