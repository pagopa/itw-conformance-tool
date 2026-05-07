import type { HttpHandler } from "@azure/functions";
import type { HttpMethod } from "@pagopa/io-wallet-utils";

import {
  PostPushedAuthorizationError,
  verifyAndSaveParRequest,
} from "@/domain/par";

import {
  createErrorResponse,
  createGenericErrorResponse,
} from "./errors/error";

export const PostPushedAuthorizationRequestHandler: HttpHandler = async (
  request,
  context,
) => {
  const entries = Array.from(request.headers.entries());
  const domHeaders = new Headers(entries);
  const bodyString = await request.text();

  try {
    const requestUriUuid = await verifyAndSaveParRequest({
      baseURL: context.app.config.baseURL,
      callbacks: context.app.callbacks,
      config: context.app.sdkConfig,
      jwksRepository: context.app.repository.jwks,
      parRequest: {
        bodyString,
        headers: domHeaders,
        method: request.method as HttpMethod,
        url: request.url,
      },
      parRequestRepository: context.app.repository.par,
    });

    return {
      headers: {
        "Content-Type": "application/json",
      },
      jsonBody: {
        expires_in: 60,
        request_uri: requestUriUuid,
      },
      status: 201,
    };
  } catch (err) {
    context.error("Error: ", err.message);

    if (err instanceof PostPushedAuthorizationError) {
      return createErrorResponse({
        error: "invalid_request",
        error_description: err.message,
        status: 400,
      });
    }

    return createGenericErrorResponse(err.message);
  }
};
