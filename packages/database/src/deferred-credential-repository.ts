import type { DatabaseClient } from './client.js';
import type { DeferredCredentialEntry, IDeferredCredentialRepository } from './interfaces.js';

type DeferredCredentialRow = {
  credentials: string;
  notification_id: string;
};

function isCredentialsArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((credential) => typeof credential === 'string');
}

function parseCredentials(transactionId: string, credentialsJson: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(credentialsJson);
  } catch (cause) {
    throw new Error(`Malformed deferred_credentials payload for transaction "${transactionId}"`, { cause });
  }

  if (!isCredentialsArray(parsed)) {
    throw new Error(`Malformed deferred_credentials payload for transaction "${transactionId}"`);
  }

  return parsed;
}

export class SqliteDeferredCredentialRepository implements IDeferredCredentialRepository {
  private readonly db: DatabaseClient;

  constructor(db: DatabaseClient) {
    this.db = db;
  }

  async consume(
    transactionId: string,
    subject: string,
    jwkThumbprint: string
  ): Promise<DeferredCredentialEntry | undefined> {
    // Single atomic statement: the row is only deleted (and returned) when the
    // transaction ID, subject, and JWK thumbprint all match, preventing replay
    // and cross-subject/cross-key retrieval.
    const row = this.db.get<DeferredCredentialRow>(
      `DELETE FROM deferred_credentials
       WHERE id = ?
         AND subject = ?
         AND jwk_thumbprint = ?
       RETURNING credentials, notification_id`,
      [transactionId, subject, jwkThumbprint]
    );

    if (!row) {
      return undefined;
    }

    return {
      credentials: parseCredentials(transactionId, row.credentials),
      jwkThumbprint,
      notificationId: row.notification_id,
      subject
    };
  }

  async insert(transactionId: string, record: DeferredCredentialEntry): Promise<void> {
    this.db.run(
      `INSERT INTO deferred_credentials (id, subject, jwk_thumbprint, notification_id, credentials)
       VALUES (?, ?, ?, ?, ?)`,
      [transactionId, record.subject, record.jwkThumbprint, record.notificationId, JSON.stringify(record.credentials)]
    );
  }
}
