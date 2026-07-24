import { wp046aScenario } from './factories/wp-046a.js';
import { wp054Scenarios } from './factories/wp-054.js';
import { wp054aInvalidStateScenario } from './factories/wp-054a.js';
import { wp054bInvalidIssuerScenario } from './factories/wp-054b.js';
import { wp059Scenario } from './factories/wp-059.js';
import { wpCiHappyScenario } from './factories/wp-ci-happy.js';
import { wpUnsupportedCredentialOfferScenario } from './factories/wp-unsupported-credential-offer.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const issuanceScenarios: ProtocolObservedScenarioDefinition[] = [
  wpCiHappyScenario,
  wp046aScenario,
  wp059Scenario,
  wpUnsupportedCredentialOfferScenario,
  ...wp054Scenarios,
  wp054aInvalidStateScenario,
  wp054bInvalidIssuerScenario
];

export const issuanceScenarioRegistry = createScenarioRegistry(issuanceScenarios);
