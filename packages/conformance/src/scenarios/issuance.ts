import { wp046aScenario } from './factories/wp-046a.js';
import { wpCiHappyScenario } from './factories/wp-ci-happy.js';
import { wpUnsupportedCredentialOfferScenario } from './factories/wp-unsupported-credential-offer.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const issuanceScenarios: ProtocolObservedScenarioDefinition[] = [
  wpCiHappyScenario,
  wp046aScenario,
  wpUnsupportedCredentialOfferScenario
];

export const issuanceScenarioRegistry = createScenarioRegistry(issuanceScenarios);
