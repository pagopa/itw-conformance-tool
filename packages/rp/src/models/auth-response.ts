export type AuthResponseErrorCode =
  | 'invalid_request_object'
  | 'invalid_request_uri'
  | 'vp_formats_not_supported'
  | 'invalid_request'
  | 'access_denied'
  | 'invalid_client';

export interface AuthResponseError {
  error: AuthResponseErrorCode;
  error_description: string;
  state: string;
}

export interface AuthResponseSuccess {
  redirect_uri: string;
}

export type AuthResponse = AuthResponseSuccess | AuthResponseError;

export function isAuthResponseError(response: AuthResponse): response is AuthResponseError {
  return 'error' in response;
}

export function isAuthResponseSuccess(response: AuthResponse): response is AuthResponseSuccess {
  return 'redirect_uri' in response;
}
