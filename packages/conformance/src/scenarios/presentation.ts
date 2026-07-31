import { wp079Scenario } from './factories/wp-079.js';
import { wp080Scenario } from './factories/wp-080.js';
import { wp081Scenario } from './factories/wp-081.js';
import { wp084Scenario } from './factories/wp-084.js';
import { wp085Scenario } from './factories/wp-085.js';
import { wp086Scenario } from './factories/wp-086.js';
import { wp087Scenario } from './factories/wp-087.js';
import { wp090Scenario } from './factories/wp-090.js';
import { wp091aScenario } from './factories/wp-091a.js';
import { wp094aScenario } from './factories/wp-094a.js';
import { wp116Scenario } from './factories/wp-116.js';
import { wpRpHappyPostScenario } from './factories/wp-rp-happy-post.js';
import { wpRpHappyScenario } from './factories/wp-rp-happy.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const presentationScenarios: ProtocolObservedScenarioDefinition[] = [
  wpRpHappyScenario,
  wpRpHappyPostScenario,
  wp079Scenario,
  wp080Scenario,
  wp081Scenario,
  wp084Scenario,
  wp085Scenario,
  wp086Scenario,
  wp087Scenario,
  wp090Scenario,
  wp091aScenario,
  wp094aScenario,
  wp116Scenario
];

export const presentationScenarioRegistry = createScenarioRegistry(presentationScenarios);
