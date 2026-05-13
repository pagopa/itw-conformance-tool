import { NotFoundError } from './errors';

interface Nonce {
  expiresAt: number;
  id: string;
}

export interface NonceRepository {
  delete: (nonce: string) => Promise<void>;
  insert: (nonce: string) => Promise<void>;
}

export const deleteExpiredNonces: (nonceRepository: NonceRepository) => Promise<void> = async (nonceRepository) => {
  const now = Date.now();
  for (const { expiresAt, id } of nonces) {
    if (expiresAt < now) {
      await nonceRepository.delete(id);
    }
  }
};

export const insertNonce: (nonce: string) => (nonceRepository: NonceRepository) => Promise<void> =
  (nonce) => (nonceRepository) =>
    nonceRepository.insert(nonce);

export const getNonce: (nonceId: string) => (nonceRepository: NonceRepository) => Promise<string> =
  (nonceId) => async (nonceRepository) => {
    await nonceRepository.delete(nonceId);
    return nonceId;
  };

// TODO: in other file (like request objects)
// fake dabatase:
export const nonces: Nonce[] = [];

export const nonceRepository: NonceRepository = {
  delete: (nonceId) => {
    const nonce = nonces.find(({ id }) => id === nonceId);
    if (!nonce) {
      return Promise.reject(new NotFoundError());
    }
    const index = nonces.findIndex((el) => el.id === nonceId);
    if (index === -1) {
      return Promise.reject(new NotFoundError());
    }
    nonces.splice(index, 1);
    return Promise.resolve(undefined);
  },
  insert: (nonceId) => {
    // we delete the nonce after 5 minutes (aligned with the request object TTL)
    nonces.push({
      expiresAt: Date.now() + 5 * 60 * 1000,
      id: nonceId
    });
    return Promise.resolve(undefined);
  }
};
