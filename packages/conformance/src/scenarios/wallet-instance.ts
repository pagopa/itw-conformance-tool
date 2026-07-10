import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const walletInstanceScenarios: ProtocolObservedScenarioDefinition[] = [];

export const walletInstanceScenarioRegistry = createScenarioRegistry(walletInstanceScenarios);
