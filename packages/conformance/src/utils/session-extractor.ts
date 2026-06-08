const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Extracts the conformance session ID (UUID) from an issuer PAR request_uri.
 *
 * The request_uri format is: urn:ietf:params:oauth:request_uri:<uuid>
 * The session ID is the UUID portion after the URN prefix.
 *
 * Returns null if the input does not match the expected format or the UUID is invalid.
 */
export function extractIssuerSessionId(requestUri: string): string | null {
  if (!requestUri.startsWith(REQUEST_URI_PREFIX)) {
    return null;
  }

  const uuid = requestUri.slice(REQUEST_URI_PREFIX.length);
  return UUID_PATTERN.test(uuid) ? uuid : null;
}

/**
 * Extracts the conformance session ID for the Relying Party flow.
 *
 * In the RP flow, the `state` value (a UUID) serves as the session identifier.
 * It is present as a path param in GET /auth/request/:state and in the
 * decrypted body of POST /auth/response.
 *
 * Returns null if the provided state is not a valid UUID.
 */
export function extractRpSessionId(state: string): string | null {
  return UUID_PATTERN.test(state) ? state : null;
}
