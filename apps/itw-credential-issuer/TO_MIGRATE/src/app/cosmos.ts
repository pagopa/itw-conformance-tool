import { CosmosClient } from '@azure/cosmos';
import { DefaultAzureCredential } from '@azure/identity';

import type { Config } from './config';

/**
 * Create and configure a CosmosClient based on the current environment.
 *
 * - In production: uses Managed Identity (AAD) via DefaultAzureCredential.
 * - In non-production: uses the Cosmos DB account key.
 */
export function createCosmosClient(config: Config): CosmosClient {
  const { endpoint, key } = config.cosmosdb;

  if (config.isDevelopment) {
    return new CosmosClient({
      endpoint,
      key
    });
  }

  // Authenticate using Azure Managed Identity in production
  const aadCredentials = new DefaultAzureCredential();
  return new CosmosClient({
    aadCredentials,
    endpoint
  });
}
