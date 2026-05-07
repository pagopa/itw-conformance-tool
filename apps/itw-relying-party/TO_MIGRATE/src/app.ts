import cors from "@fastify/cors";
import fastifyFormbody from "@fastify/formbody";
import fastifyStatic from "@fastify/static";
import * as dotenv from "dotenv";
import Fastify from "fastify";
import * as path from "path";
import * as z from "zod";

import { getConfig } from "./config";
import { BadRequestError, onError } from "./errors";
import { createAuthorizationRequest } from "./infra/handlers/create-authorization-request";
import { getAuthorizationRequest } from "./infra/handlers/get-authorization-request";
import { getStatus } from "./infra/handlers/get-status";
import { health } from "./infra/handlers/health";
import { sendAuthorizationResponse } from "./infra/handlers/send-authorization-response";
import { deleteExpiredNonces, nonceRepository } from "./nonce";
import { markAsExpired } from "./request-object";
import { requestObjectRepository } from "./request-object";
import { AuthorizationRequest, responseBody } from "./schemas";

dotenv.config();

const config = getConfig(process.env);

const fastify = Fastify({
  logger: false,
});

fastify.register(cors, {
  origin: "*",
});

fastify.register(fastifyStatic, {
  root: path.join(import.meta.dirname, "../public"),
});

fastify.register(fastifyFormbody);

fastify.setErrorHandler(onError);

setInterval(async () => {
  await markAsExpired(requestObjectRepository);
}, 10000);

// every minute it deletes all nonces
setInterval(async () => {
  await deleteExpiredNonces(nonceRepository);
}, 60000);

// wallet endpoints
// endpoint that returns request object
fastify.get(getAuthorizationRequest.path, async (request, reply) => {
  const parsedParams = z
    .object({
      params: z.object({
        state: z.string(),
      }),
    })
    .safeParse(request);
  if (!parsedParams.success) {
    throw new BadRequestError();
  }
  const state = parsedParams.data.params.state;
  const jwt = await getAuthorizationRequest.handler(state)({
    requestObjectRepository,
  });
  return reply
    .code(200)
    .header("content-type", "application/oauth-authz-req+jwt")
    .send(jwt);
});

// authorization response endpoint
fastify.post(sendAuthorizationResponse.path, (request) => {
  const parsedBody = responseBody.safeParse(request.body);
  if (!parsedBody.success) {
    throw new BadRequestError("The request is missing required parameters");
  }
  const body = parsedBody.data;
  return sendAuthorizationResponse.handler(body)({
    config,
    nonceRepository,
    requestObjectRepository,
  });
});

// other endpoints:
// endpoint that creates request object
fastify.post(createAuthorizationRequest.path, (request) => {
  const parsedBody = AuthorizationRequest.safeParse(request.body);
  if (!parsedBody.success) {
    throw new BadRequestError("DCQL is not correct");
  }
  return createAuthorizationRequest.handler(parsedBody.data)({
    config,
    nonceRepository,
    requestObjectRepository,
  });
});

// status endpoint
fastify.get(getStatus.path, (request) => {
  const parsedParams = z
    .object({
      params: z.object({
        state: z.string(),
      }),
    })
    .safeParse(request);
  if (!parsedParams.success) {
    throw new Error();
  }
  const state = parsedParams.data.params.state;
  return getStatus.handler(state)(requestObjectRepository);
});

// health check
fastify.get(health.path, health.handler);

const port = Number(process.env.PORT || 8080);

fastify.listen({ host: "0.0.0.0", port }, function (err) {
  // eslint-disable-next-line no-console
  console.log("listening on port", port);
  if (err) {
    fastify.log.error(err);
    process.exit(1);
  }
});
