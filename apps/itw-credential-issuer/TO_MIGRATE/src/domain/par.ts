import {
  CallbackContext,
  JwtSignerJwk,
  decodeJwt,
  parsePushedAuthorizationRequest,
  verifyPushedAuthorizationRequest,
} from "@pagopa/io-wallet-oauth2";
import { HttpMethod, IoWalletSdkConfig } from "@pagopa/io-wallet-utils";
import { randomUUID } from "crypto";

import { getEntityConfigurationClaimsMetadata } from "./openid-federation";
import { JwksRepository } from "./signer";
import { ParRequest, getPushedAuthorizationRequestSchema } from "./z-par";

export class PostPushedAuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PostPushedAuthorizationError";

    Object.setPrototypeOf(this, PostPushedAuthorizationError.prototype);
  }
}

export interface ParRequestRepository {
  readonly consumeByCode: (code: string) => Promise<ParRequest>;
  readonly get: (query: {
    code?: string;
    jti?: string;
    requestUri?: string;
  }) => Promise<ParRequest>;
  readonly insert: (data: ParRequest) => Promise<string>;
  readonly update: (data: ParRequest) => Promise<void>;
}

export interface VerifyAndSaveParRequestOptions {
  /* * The body of the request, as a string. */
  baseURL: string;

  callbacks: Pick<CallbackContext, "fetch" | "hash" | "verifyJwt">;

  config: IoWalletSdkConfig;

  /* Public key used to verify the JWT. */
  jwksRepository: JwksRepository;

  /* The Pushed Authorization Request (PAR) request. */
  parRequest: {
    bodyString: string;
    headers: Headers;
    method: HttpMethod;
    url: string;
  };

  /* Repository for storing Pushed Authorization Requests. */
  parRequestRepository: ParRequestRepository;
}

export const verifyAndSaveParRequest = async (
  options: VerifyAndSaveParRequestOptions,
): Promise<string> => {
  const parRequestFormUrl = Object.fromEntries(
    new URLSearchParams(options.parRequest.bodyString),
  );

  const clientId = parRequestFormUrl.client_id;
  const signedRequestJwt = parRequestFormUrl.request;

  if (!clientId || !signedRequestJwt) {
    throw new PostPushedAuthorizationError(
      "client_id and request are required",
    );
  }

  const { authorizationRequest, authorizationRequestJwt, clientAttestation } =
    await parsePushedAuthorizationRequest({
      authorizationRequest: parRequestFormUrl,
      callbacks: options.callbacks,
      config: options.config,
      request: {
        headers: options.parRequest.headers,
        method: options.parRequest.method,
        url: options.parRequest.url,
      },
    });

  if (!authorizationRequestJwt) {
    throw new PostPushedAuthorizationError(
      "signed authorization request is required",
    );
  }

  if (!clientAttestation) {
    throw new PostPushedAuthorizationError("client attestation is required");
  }

  // Reject replayed JWTs: a jti that has already been used must not be accepted
  const existingParByJti = await options.parRequestRepository
    .get({ jti: authorizationRequest.jti })
    .catch(() => undefined);
  if (existingParByJti !== undefined) {
    throw new PostPushedAuthorizationError(
      `PAR request with jti "${authorizationRequest.jti}" has already been used`,
    );
  }

  const federationMetadata = getEntityConfigurationClaimsMetadata(
    options.baseURL,
    options.jwksRepository,
    options.config,
  );

  const publicJwk = decodeJwt({
    jwt: clientAttestation.walletAttestationJwt,
  }).payload.cnf.jwk;

  const signer: JwtSignerJwk = {
    alg: "ES256",
    method: "jwk",
    publicJwk,
  };

  await verifyPushedAuthorizationRequest({
    authorizationRequest,
    authorizationRequestJwt: {
      jwt: authorizationRequestJwt,
      signer,
    },
    authorizationServerMetadata: federationMetadata.oauth_authorization_server,
    callbacks: options.callbacks,
    clientAttestation: {
      ...clientAttestation,
      ensureConfirmationKeyMatchesDpopKey: true,
    },
    config: options.config,
    request: {
      headers: options.parRequest.headers,
      method: options.parRequest.method,
      url: options.parRequest.url,
    },
  });

  const requestUri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`;
  const parSchema = getPushedAuthorizationRequestSchema(options.config);
  const storedParRequest = parSchema.parse({
    ...authorizationRequest,
    id: randomUUID(),
    request_uri: requestUri,
  });

  await options.parRequestRepository.insert(storedParRequest);

  return requestUri;
};
