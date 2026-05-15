import { randomBytes } from 'node:crypto';

import { NONCE_TTL_MS } from '../models/nonce.js';

import type { INonceRepository } from '@itw-conformance-tool/database';

export class InvalidNonceError extends Error {
  constructor(nonce: string) {
    super(`Nonce "${nonce}" is invalid or has already been consumed`);
    this.name = 'InvalidNonceError';
    Object.setPrototypeOf(this, InvalidNonceError.prototype);
  }
}

export class NonceService {
  readonly #nonceRepository: INonceRepository;

  constructor(nonceRepository: INonceRepository) {
    this.#nonceRepository = nonceRepository;
  }

  async generate(ttlMs = NONCE_TTL_MS): Promise<string> {
    const value = randomBytes(32).toString('hex');
    await this.#nonceRepository.insert(value, Date.now() + ttlMs);
    return value;
  }

  async consume(value: string): Promise<void> {
    const consumed = await this.#nonceRepository.consume(value);
    if (!consumed) {
      throw new InvalidNonceError(value);
    }
  }
}
