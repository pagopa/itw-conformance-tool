import { HttpResponseInit } from "@azure/functions";

interface ErrorResponseParams {
  error: string;
  error_description: string;
  status: number;
}

export const createErrorResponse = ({
  error,
  error_description,
  status,
}: ErrorResponseParams): HttpResponseInit => ({
  headers: {
    "Content-Type": "application/json",
  },
  jsonBody: {
    error,
    error_description,
  },
  status,
});

export const createErrorLocationResponse = (
  redirect_uri: string,
  state: string,
  params: ErrorResponseParams,
): HttpResponseInit => ({
  headers: {
    Location: `${redirect_uri}?error=${params.error}&state=${state}&error_description=${params.error_description}`,
  },
  status: 302,
});

export const createGenericErrorResponse = (
  errorMessage?: string,
): HttpResponseInit => ({
  headers: {
    "Content-Type": "application/json",
  },
  jsonBody: {
    error: "server error",
    error_description: errorMessage ?? "Generic error!",
  },
  status: 500,
});

export const createInvalidGrantResponse = (
  errorDescription?: string,
): HttpResponseInit => ({
  headers: {
    "Cache-Control": "no-store",
    "Content-Type": "application/json",
    Pragma: "no-cache",
  },
  jsonBody: {
    error: "invalid_grant",
    error_description:
      errorDescription ??
      "The authorization grant is invalid, expired, or has already been used.",
  },
  status: 400,
});

export const createUnsupportedGrantTypeResponse = (
  errorDescription?: string,
): HttpResponseInit => ({
  headers: {
    "Cache-Control": "no-store",
    "Content-Type": "application/json",
    Pragma: "no-cache",
  },
  jsonBody: {
    error: "unsupported_grant_type",
    error_description:
      errorDescription ??
      "The authorization grant type is not supported by the authorization server.",
  },
  status: 400,
});

export const createInvalidProofResponse = (
  errorDescription?: string,
): HttpResponseInit => ({
  headers: {
    "Content-Type": "application/json",
  },
  jsonBody: {
    error: "invalid_proof",
    error_description:
      errorDescription ??
      "The proof of possession is invalid, malformed, or uses an untrusted key.",
  },
  status: 400,
});
