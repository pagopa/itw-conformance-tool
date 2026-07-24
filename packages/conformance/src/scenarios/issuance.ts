import { wp046aScenario } from './factories/wp-046a.js';
import { wp054Scenarios } from './factories/wp-054.js';
import { wpCiHappyScenario } from './factories/wp-ci-happy.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const issuanceScenarios: ProtocolObservedScenarioDefinition[] = [
  wpCiHappyScenario,
  wp046aScenario,
  ...wp054Scenarios
];

export const issuanceScenarioRegistry = createScenarioRegistry(issuanceScenarios);
