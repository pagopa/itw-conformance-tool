import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DDL } from './schema.js';

type SqlValue = string | number | bigint | null | Uint8Array;
type SqlParams = SqlValue[] | Record<string, SqlValue>;

export interface DatabaseClientOptions {
  readonly readOnly?: boolean;
  readonly timeout?: number;
  readonly readBigInts?: boolean;
}

export class DatabaseClient {
  private readonly db: DatabaseSync;

  constructor(path: string, options: DatabaseClientOptions = {}) {
    this.db = new DatabaseSync(this.resolvePath(path), {
      readOnly: options.readOnly ?? false,
      timeout: options.timeout ?? 5_000,
      readBigInts: options.readBigInts ?? false,
      enableForeignKeyConstraints: true
    });

    this.exec('PRAGMA journal_mode = WAL');
    this.exec('PRAGMA synchronous = NORMAL');
    this.exec(DDL);
  }

  private resolvePath(path: string) {
    if (path === ':memory:') {
      return ':memory';
    }

    mkdirSync(path, { recursive: true });
    return join(path, 'itw.db');
  }

  exec(sql: string): void {
    this.db.exec(sql);
  }

  query<T = Record<string, unknown>>(sql: string, params: SqlParams = []): T[] {
    const stmt = this.db.prepare(sql);

    if (Array.isArray(params)) {
      return stmt.all(...params) as T[];
    }

    return stmt.all(params) as T[];
  }

  get<T = Record<string, unknown>>(sql: string, params: SqlParams = []): T | undefined {
    const stmt = this.db.prepare(sql);

    const row = Array.isArray(params) ? stmt.get(...params) : stmt.get(params);

    return row as T | undefined;
  }

  run(
    sql: string,
    params: SqlParams = []
  ): {
    changes: number | bigint;
    lastInsertRowid: number | bigint;
  } {
    const stmt = this.db.prepare(sql);

    const result = Array.isArray(params) ? stmt.run(...params) : stmt.run(params);

    return {
      changes: result.changes,
      lastInsertRowid: result.lastInsertRowid
    };
  }

  transaction<T>(callback: () => T): T {
    this.exec('BEGIN');

    try {
      const result = callback();
      this.exec('COMMIT');
      return result;
    } catch (error) {
      this.exec('ROLLBACK');
      throw error;
    }
  }

  close(): void {
    if (this.db.isOpen) {
      this.db.close();
    }
  }
}
