/**
 * An OpenID Connect / OpenID4VP request object: the signed JWT and the
 * decoded header + payload claims.
 */
export interface RequestObject {
  jwt: string;
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
}

export function createRequestObject(
  jwt: string,
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {}
): RequestObject {
  return { jwt, header, claims };
}
