import type { ParRequest } from "@/domain/z-par";
import type { HttpHandler } from "@azure/functions";

import { getFormPostFromRedirectUriAndJwt } from "@/domain/utils/form_post_jwt";
import { randomUUID } from "crypto";
import { SignJWT, importJWK } from "jose";

import {
  createErrorResponse,
  createGenericErrorResponse,
} from "./errors/error";

export const GetAuthorizationCodeJwtHandler: HttpHandler = async (
  request,
  context,
) => {
  const request_uri = request.query.get("request_uri");

  if (!request_uri) {
    return createErrorResponse({
      error: "invalid_request",
      error_description: "client_id and request_uri are required",
      status: 400,
    });
  }

  try {
    const parRequest: ParRequest = await context.app.repository.par.get({
      requestUri: request_uri,
    });

    if (!parRequest || !parRequest.redirect_uri) {
      return createErrorResponse({
        error: "invalid_request",
        error_description: "request_uri not found",
        status: 400,
      });
    }

    const code = randomUUID();
    parRequest.code = code;
    parRequest.code_expires_at = Math.floor(Date.now() / 1000) + 300;

    const { private: privateSig } = context.app.repository.jwks.getSign();
    const importSig = await importJWK(privateSig);
    const jwt = await new SignJWT({
      code: code,
      ...(parRequest.state ? { state: parRequest.state } : {}),
    })
      .setIssuer(context.app.config.baseURL)
      .setIssuedAt()
      .setExpirationTime("5m")
      .setProtectedHeader({
        alg: "ES256",
      })
      .sign(importSig);

    await context.app.repository.par.update(parRequest);

    return {
      body: getFormPostFromRedirectUriAndJwt(parRequest.redirect_uri, jwt),
      status: 200,
    };
  } catch (err) {
    context.error("Error: ", err.message);
    return createGenericErrorResponse(err.message);
  }
};
