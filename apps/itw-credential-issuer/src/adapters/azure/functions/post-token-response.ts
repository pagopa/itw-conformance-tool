import type { HttpHandler } from "@azure/functions";
import type { HttpMethod } from "@pagopa/io-wallet-utils";

import {
  InvalidGrantError,
  UnsupportedGrantTypeError,
  createAccessToken,
} from "@/domain/token";

import {
  createGenericErrorResponse,
  createInvalidGrantResponse,
  createUnsupportedGrantTypeResponse,
} from "./errors/error";

export const PostTokenResponseHandler: HttpHandler = async (
  request,
  context,
) => {
  const entries = Array.from(request.headers.entries());
  const domHeaders = new Headers(entries);

  const requestLike = {
    bodyString: await request.text(),
    headers: domHeaders,
    method: request.method as HttpMethod,
    url: request.url,
  };

  try {
    const accessTokenResponse = await createAccessToken({
      baseURL: context.app.config.baseURL,
      callbacks: context.app.callbacks,
      config: context.app.sdkConfig,
      jwksRepository: context.app.repository.jwks,
      parRequestRepository: context.app.repository.par,
      tokenRequest: requestLike,
    });

    return {
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
      },
      jsonBody: accessTokenResponse,
      status: 200,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    context.error("Error: ", message);
    if (err instanceof InvalidGrantError) {
      return createInvalidGrantResponse(message);
    }
    if (err instanceof UnsupportedGrantTypeError) {
      return createUnsupportedGrantTypeResponse(message);
    }
    return createGenericErrorResponse(message);
  }
};
