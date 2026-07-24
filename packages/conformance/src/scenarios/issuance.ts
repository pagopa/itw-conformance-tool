import { wp046aScenario } from './factories/wp-046a.js';
import { wpCiHappyScenario } from './factories/wp-ci-happy.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const issuanceScenarios: ProtocolObservedScenarioDefinition[] = [wpCiHappyScenario, wp046aScenario];

export const issuanceScenarioRegistry = createScenarioRegistry(issuanceScenarios);
