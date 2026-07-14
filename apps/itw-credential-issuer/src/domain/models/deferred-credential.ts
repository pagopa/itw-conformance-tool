export interface DeferredCredentialRequestBody {
  transaction_id: string;
}

/**
 * Protocol error code returned by `POST /deferred` for any missing, unknown,
 * mismatched, or already-consumed `transaction_id`, without revealing which
 * condition occurred.
 */
export const INVALID_TRANSACTION_ID_ERROR = 'invalid_transaction_id';
