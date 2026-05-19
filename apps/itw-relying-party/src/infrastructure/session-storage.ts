import { existsSync, mkdirSync } from 'node:fs';

import {
  DatabaseClient,
  SqliteSessionRepository as DatabaseSessionRepository,
  type SessionState
} from '@itw-conformance-tool/database';

export class SqliteSessionRepository {
  readonly #client: DatabaseClient;
  readonly #repository: DatabaseSessionRepository;

  constructor(dataDir: string) {
    if (!existsSync(dataDir)) {
      mkdirSync(dataDir, { recursive: true });
    }

    this.#client = new DatabaseClient({ dataDir });
    this.#repository = new DatabaseSessionRepository(this.#client.db);
  }

  async delete(id: string): Promise<void> {
    await this.#repository.delete(id);
  }

  async get(id: string) {
    return this.#repository.get(id);
  }

  async insert(id: string, requestObject?: string): Promise<void> {
    await this.#repository.insert(id, requestObject);
  }

  async update(id: string, state: SessionState, response?: string): Promise<void> {
    await this.#repository.update(id, state, response);
  }

  close(): void {
    this.#client.close();
  }
}
