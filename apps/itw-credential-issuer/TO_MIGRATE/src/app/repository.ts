import type { NonceRepository } from '@/domain/nonce';
import type { ParRequestRepository } from '@/domain/par';
import type { JwksRepository } from '@/domain/signer';
import type { CosmosClient } from '@azure/cosmos';

import { makeNonceRepository } from '@/adapters/azure/cosmosdb/nonce';
import { makeParRequestRepository } from '@/adapters/azure/cosmosdb/par';
import { makeJwksRepository } from '@/adapters/in-memory/signer';

import { config } from './config';
import { createCosmosClient } from './cosmos';

export class AppRepository {
  private cosmosDB: CosmosClient;
  private jwksRepository: JwksRepository;
  private nonceRepository: NonceRepository;
  private parRequestRepository: ParRequestRepository;

  constructor() {
    this.cosmosDB = createCosmosClient(config);
    this.jwksRepository = this.buildJwksRepository();
    this.nonceRepository = this.buildNonceRepository();
    this.parRequestRepository = this.buildParRequestRepository();
  }

  private buildJwksRepository() {
    return makeJwksRepository(config.signer.jwks, config.encrypter.jwks, config.cert.iacaX509);
  }

  private buildNonceRepository() {
    return makeNonceRepository(this.cosmosDB.database(config.cosmosdb.databaseName));
  }

  private buildParRequestRepository() {
    return makeParRequestRepository(this.cosmosDB.database(config.cosmosdb.databaseName));
  }

  public get jwks() {
    return this.jwksRepository;
  }

  public get nonce() {
    return this.nonceRepository;
  }

  public get par() {
    return this.parRequestRepository;
  }
}
