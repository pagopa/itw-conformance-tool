export interface Nonce {
  readonly value: string;
  readonly expiresAt: number;
}

export const NONCE_TTL_MS = 300_000; // 5 minutes

export function createNonce(value: string, ttlMs = NONCE_TTL_MS): Nonce {
  return { value, expiresAt: Date.now() + ttlMs };
}
