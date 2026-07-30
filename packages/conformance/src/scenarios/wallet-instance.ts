import { wpWalletProviderHappyScenario } from './factories/wp-wallet-provider-happy.js';
import { createScenarioRegistry } from './registry.js';

import type { ProtocolObservedScenarioDefinition } from './definitions.js';

export const walletInstanceScenarios: ProtocolObservedScenarioDefinition[] = [wpWalletProviderHappyScenario];

export const walletInstanceScenarioRegistry = createScenarioRegistry(walletInstanceScenarios);
