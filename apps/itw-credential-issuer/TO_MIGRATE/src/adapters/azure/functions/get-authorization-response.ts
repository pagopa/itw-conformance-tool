import type { HttpHandler } from "@azure/functions";

import {
  handleEAAAuthorizationResponse,
  handlePIDAuthorizationResponse,
} from "@/domain/authorization";
import { SupportedCredentialsId } from "@/domain/z-credential";

import {
  createErrorLocationResponse,
  createErrorResponse,
  createGenericErrorResponse,
} from "./errors/error";

export const GetAuthorizationResponseHandler: HttpHandler = async (
  request,
  context,
) => {
  const clientId = request.query.get("client_id");
  const request_uri = request.query.get("request_uri");

  if (!clientId || !request_uri) {
    return createErrorResponse({
      error: "invalid_request",
      error_description: "client_id and request_uri are required",
      status: 400,
    });
  }

  try {
    const parRequest = await context.app.repository.par.get({
      requestUri: request_uri,
    });

    if (!parRequest) {
      return createErrorResponse({
        error: "invalid_request",
        error_description: "request_uri not found",
        status: 400,
      });
    }

    if (clientId !== parRequest.client_id) {
      return createErrorLocationResponse(
        parRequest.redirect_uri,
        parRequest.state,
        {
          error: "invalid_request",
          error_description: "client_id does not match",
          status: 400,
        },
      );
    }

    if (!parRequest.authorization_details?.length) {
      return createErrorLocationResponse(
        parRequest.redirect_uri,
        parRequest.state,
        {
          error: "invalid_request",
          error_description: "missing authorization_details",
          status: 400,
        },
      );
    }

    if (parRequest.authorization_details[0].type !== "openid_credential") {
      return createErrorLocationResponse(
        parRequest.redirect_uri,
        parRequest.state,
        {
          error: "invalid_request",
          error_description: "unsupported credential type",
          status: 400,
        },
      );
    }

    const credentialConfigurationId =
      parRequest.authorization_details?.[0].credential_configuration_id;

    const result = SupportedCredentialsId.safeParse(credentialConfigurationId);
    if (result.data === "dc_sd_jwt_PersonIdentificationData") {
      return await handlePIDAuthorizationResponse(context, parRequest);
    }

    return await handleEAAAuthorizationResponse(
      context,
      parRequest,
      request_uri,
    );
  } catch (err) {
    context.error("Error: ", err.message);
    return createGenericErrorResponse(err.message);
  }
};
