/**
 * Represents an OpenID Connect authorization response.
 * Contains the response code and any error details.
 */
export interface AuthResponse {
  code?: string;
  error?: string;
  errorDescription?: string;
  state?: string;
}

/**
 * Constructs a successful authorization response with a code.
 */
export function createSuccessAuthResponse(code: string, state?: string): AuthResponse {
  return {
    code,
    state
  };
}

/**
 * Constructs an error authorization response.
 */
export function createErrorAuthResponse(error: string, errorDescription?: string, state?: string): AuthResponse {
  return {
    error,
    errorDescription,
    state
  };
}
