import type { DatabaseClient } from '@itw-conformance-tool/database';

interface Nonce {
  expiresAt: number;
  id: string;
}

export class NonceRepository {
  private readonly db: DatabaseClient;

  constructor(db: DatabaseClient) {
    this.db = db;
  }

  public list(): Nonce[] {
    return this.db
      .query<{ expires_at: number; id: string }>('SELECT id, expires_at FROM relying_party_nonces')
      .map((row) => ({
        expiresAt: row.expires_at,
        id: row.id
      }));
  }

  public get(nonceId: string): Nonce {
    const nonce = this.db.get<{ expires_at: number; id: string }>(
      'SELECT id, expires_at FROM relying_party_nonces WHERE id = ?',
      [nonceId]
    );
    if (!nonce) {
      throw new Error(`Nonce ${nonceId} not found`);
    }

    return { expiresAt: nonce.expires_at, id: nonce.id };
  }

  public delete(nonceId: string): void {
    const result = this.db.run('DELETE FROM relying_party_nonces WHERE id = ?', [nonceId]);
    if (result.changes === 0) {
      throw new Error(`Nonce ${nonceId} not found`);
    }
  }

  public insert(nonceId: string): void {
    // We delete the nonce after 5 minutes (aligned with the request object TTL).
    this.db.run('INSERT INTO relying_party_nonces (id, expires_at) VALUES (?, ?)', [
      nonceId,
      Date.now() + 5 * 60 * 1000
    ]);
  }

  public deleteExpiredNonces(): void {
    this.db.run('DELETE FROM relying_party_nonces WHERE expires_at < ?', [Date.now()]);
  }
}
