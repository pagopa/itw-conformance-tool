import { DatabaseClient, SqliteNonceRepository as DatabaseNonceRepository } from '@itw-conformance-tool/database';

export class SqliteNonceRepository {
  readonly #client: DatabaseClient;
  readonly #repository: DatabaseNonceRepository;

  constructor(dataDir: string) {
    this.#client = new DatabaseClient(dataDir);
    this.#repository = new DatabaseNonceRepository(this.#client);
  }

  async consume(value: string): Promise<boolean> {
    return this.#repository.consume(value);
  }

  async delete(value: string): Promise<void> {
    await this.#repository.delete(value);
  }

  async get(value: string): Promise<string | undefined> {
    return this.#repository.get(value);
  }

  async insert(value: string, expiresAtMs: number): Promise<void> {
    await this.#repository.insert(value, expiresAtMs);
  }

  close(): void {
    this.#client.close();
  }
}
