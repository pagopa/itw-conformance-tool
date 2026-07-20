import { wpCiHappyScenario } from './factories/wp-ci-happy.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const issuanceScenarios: ProtocolObservedScenarioDefinition[] = [wpCiHappyScenario];

export const issuanceScenarioRegistry = createScenarioRegistry(issuanceScenarios);
