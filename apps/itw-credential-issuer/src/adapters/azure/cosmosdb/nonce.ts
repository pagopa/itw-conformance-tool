import { NonceRepository } from "@/domain/nonce";
import { Database } from "@azure/cosmos";

/**
 * Creates a NonceRepository backed by Azure CosmosDB.
 * @param db - The CosmosDB database instance.
 * @param containerName - (Optional) Name of the container to use. Defaults to "nonces".
 * @returns An implementation of NonceRepository.
 */
export const makeNonceRepository = (
  db: Database,
  containerName = "nonces",
): NonceRepository => {
  const container = db.container(containerName);

  return {
    async delete(id: string): Promise<void> {
      await container.item(id, id).delete();
    },
    async get(id: string): Promise<string | undefined> {
      const { resource: readDoc } = await container.item(id, id).read();
      if (!readDoc) return undefined;
      return readDoc.id;
    },
    async insert(nonce: string): Promise<string> {
      await container.items.create({ id: nonce });
      return nonce;
    },
  };
};
