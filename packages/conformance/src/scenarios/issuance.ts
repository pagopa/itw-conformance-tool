import { wp046aScenario } from './factories/wp-046a.js';
import { wp054Scenarios } from './factories/wp-054.js';
import { wp054aInvalidStateScenario } from './factories/wp-054a.js';
import { wp054bInvalidIssuerScenario } from './factories/wp-054b.js';
import { wp059Scenario } from './factories/wp-059.js';
import { wp060Scenarios } from './factories/wp-060.js';
import { wp061Scenario } from './factories/wp-061.js';
import { wp062aScenario } from './factories/wp-062a.js';
import { wp062bScenario } from './factories/wp-062b.js';
import { wpCiHappyScenario } from './factories/wp-ci-happy.js';
import { wpCredentialReissuanceScenario } from './factories/wp-credential-reissuance.js';
import { wpDeferredScenario } from './factories/wp-deferred.js';
import { wpNotificationScenario } from './factories/wp-notification.js';
import { wpUnsupportedCredentialOfferScenario } from './factories/wp-unsupported-credential-offer.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const issuanceScenarios: ProtocolObservedScenarioDefinition[] = [
  wpCiHappyScenario,
  wp046aScenario,
  wp059Scenario,
  ...wp060Scenarios,
  wp061Scenario,
  wp062aScenario,
  wp062bScenario,
  wpNotificationScenario,
  wpCredentialReissuanceScenario,
  wpDeferredScenario,
  wpUnsupportedCredentialOfferScenario,
  ...wp054Scenarios,
  wp054aInvalidStateScenario,
  wp054bInvalidIssuerScenario
];

export const issuanceScenarioRegistry = createScenarioRegistry(issuanceScenarios);
