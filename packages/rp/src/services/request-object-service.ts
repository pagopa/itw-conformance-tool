import { createRequestObject, type RequestObject } from '../models/request-object.js';

export class InvalidRequestObjectJwtError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidRequestObjectJwtError';
    Object.setPrototypeOf(this, InvalidRequestObjectJwtError.prototype);
  }
}

function decodeJwtSegment(segment: string): Record<string, unknown> {
  const json = Buffer.from(segment, 'base64url').toString('utf-8');
  if (json.length === 0) {
    throw new InvalidRequestObjectJwtError('Empty JWT segment');
  }
  const parsed = JSON.parse(json) as unknown;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new InvalidRequestObjectJwtError('Decoded JWT segment is not a JSON object');
  }
  return parsed as Record<string, unknown>;
}

/**
 * Parses and validates OpenID4VP request objects. Signature verification is
 * out of scope here — it requires a JWKS resolver and a trust chain, which
 * are not modelled in this package yet.
 */
export class RequestObjectService {
  /**
   * Decodes the JWT header and payload (no signature verification).
   * Throws InvalidRequestObjectJwtError if the JWT is structurally invalid.
   */
  parse(jwt: string): RequestObject {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new InvalidRequestObjectJwtError('JWT must have three dot-separated segments');
    }

    let header: Record<string, unknown>;
    let claims: Record<string, unknown>;

    try {
      header = decodeJwtSegment(parts[0]);
    } catch (cause) {
      throw new InvalidRequestObjectJwtError(
        `Cannot decode JWT header: ${cause instanceof Error ? cause.message : String(cause)}`
      );
    }

    try {
      claims = decodeJwtSegment(parts[1]);
    } catch (cause) {
      throw new InvalidRequestObjectJwtError(
        `Cannot decode JWT payload: ${cause instanceof Error ? cause.message : String(cause)}`
      );
    }

    return createRequestObject(jwt, claims, header);
  }

  /**
   * Structural validation of an already-parsed request object: ensures the
   * JWT keeps three segments, the header carries `alg`, and the payload has
   * the OpenID4VP-required `client_id` and `nonce` claims.
   */
  validate(requestObject: RequestObject): boolean {
    if (requestObject.jwt.split('.').length !== 3) {
      return false;
    }
    if (typeof requestObject.header['alg'] !== 'string' || requestObject.header['alg'].length === 0) {
      return false;
    }
    if (typeof requestObject.claims['client_id'] !== 'string' || requestObject.claims['client_id'].length === 0) {
      return false;
    }
    if (typeof requestObject.claims['nonce'] !== 'string' || requestObject.claims['nonce'].length === 0) {
      return false;
    }
    return true;
  }
}
