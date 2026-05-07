import { ParRequestRepository } from "@/domain/par";
import { InvalidGrantError } from "@/domain/token";
import { ParRequest } from "@/domain/z-par";
import { Database, RestError } from "@azure/cosmos";

export const makeParRequestRepository = (
  db: Database,
  containerName = "par-requests",
): ParRequestRepository => {
  const container = db.container(containerName);
  const getConsumedAt = () => Math.floor(Date.now() / 1000);

  return {
    async consumeByCode(code: string): Promise<ParRequest> {
      const { resources } = await container.items
        .query({
          parameters: [
            {
              name: "@code",
              value: code,
            },
          ],
          query: "SELECT * FROM c WHERE c.code = @code",
        })
        .fetchAll();

      if (resources.length === 0) {
        throw new InvalidGrantError(
          `No Pushed Authorization Request found for code: ${code}`,
        );
      }

      if (resources.length > 1) {
        throw new Error(`Multiple items found with code: ${code}`);
      }

      const storedParRequest = resources[0];

      if (storedParRequest.code_consumed_at !== undefined) {
        throw new InvalidGrantError(
          `Authorization code has already been used: ${code}`,
        );
      }

      if (storedParRequest.code_expires_at === undefined) {
        throw new InvalidGrantError(
          `Authorization code is missing expiry metadata: ${code}`,
        );
      }

      const currentTime = Math.floor(Date.now() / 1000);
      if (currentTime > storedParRequest.code_expires_at) {
        throw new InvalidGrantError(
          `Authorization code has expired at: ${storedParRequest.code_expires_at}`,
        );
      }

      const consumedAt = getConsumedAt();
      const updatedParRequest: ParRequest = {
        ...storedParRequest,
        code_consumed_at: consumedAt,
      };

      try {
        const response = await container
          .item(storedParRequest.id, storedParRequest.clientId)
          .replace(updatedParRequest, {
            accessCondition: {
              condition: storedParRequest._etag,
              type: "IfMatch",
            },
          });

        return ParRequest.parse(response.resource);
      } catch (error) {
        if (error instanceof RestError && error.statusCode === 412) {
          throw new InvalidGrantError(
            `Authorization code has already been used: ${code}`,
          );
        }

        throw error;
      }
    },
    async get(query: {
      code?: string;
      jti?: string;
      requestUri?: string;
    }): Promise<ParRequest> {
      const querySpec = {
        parameters: [
          {
            name: "@requestUri",
            value: query.requestUri,
          },
          {
            name: "@code",
            value: query.code,
          },
          {
            name: "@jti",
            value: query.jti,
          },
        ],
        query:
          "SELECT * FROM c WHERE 1=1" +
          (query.requestUri ? " AND c.request_uri = @requestUri" : "") +
          (query.code ? " AND c.code = @code" : "") +
          (query.jti ? " AND c.jti = @jti" : ""),
      };
      const { resources } = await container.items.query(querySpec).fetchAll();
      if (resources.length === 0) {
        throw new Error(
          `No item found with request_uri: ${query.requestUri} or code: ${query.code}`,
        );
      }
      return ParRequest.parse(resources[0]);
    },
    async insert(data: ParRequest): Promise<string> {
      const { resource } = await container.items.create({
        ...data,
        clientId: data.client_id,
      });
      return resource.request_uri;
    },
    async update(data: ParRequest): Promise<void> {
      await container.items.upsert(data);
    },
  };
};
