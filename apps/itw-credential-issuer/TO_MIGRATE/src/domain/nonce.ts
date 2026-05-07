import crypto from "crypto";

/**
 * Options for generating a nonce.
 */
export interface NonceOptions {
  /** The repository used to persist and retrieve nonces. */
  readonly nonceRepository: NonceRepository;
}

/**
 * Repository interface for nonce storage and retrieval.
 */
export interface NonceRepository {
  /**
   * Deletes a nonce by its ID, consuming it so it cannot be reused.
   * @param id - The nonce ID to delete.
   */
  readonly delete: (id: string) => Promise<void>;
  /**
   * Retrieves a nonce by its ID.
   * @param id - The nonce ID.
   * @returns A promise that resolves to the nonce string or undefined if not found.
   */
  readonly get: (id: string) => Promise<string>;
  /**
   * Inserts a new nonce.
   * @param id - The nonce string to store.
   * @returns A promise that resolves to the stored nonce string.
   */
  readonly insert: (id: string) => Promise<string>;
}

/**
 * Generates a cryptographically secure nonce, stores it using the provided repository, and returns it.
 * @param options - NonceOptions including the repository implementation.
 * @returns The generated nonce string.
 */
export const generateNonce = (options: NonceOptions): Promise<string> => {
  const nonce = crypto.randomBytes(32).toString("hex");

  return options.nonceRepository.insert(nonce);
};
