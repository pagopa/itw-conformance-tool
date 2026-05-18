import { decodeJwt } from 'jose';

import { validateRequestObject, isRequestObjectExpired, type RequestObject } from '../models/index.js';

export class InvalidRequestObjectJwtError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidRequestObjectJwtError';
  }
}

export class RequestObjectService {
  decodeAndValidate(requestObjectJwt: string): RequestObject {
    if (!requestObjectJwt) {
      throw new InvalidRequestObjectJwtError('Request object JWT is empty');
    }

    let payload: unknown;
    try {
      payload = decodeJwt(requestObjectJwt);
    } catch (error) {
      throw new InvalidRequestObjectJwtError(
        `Failed to decode request object JWT: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    let requestObject: RequestObject;
    try {
      requestObject = validateRequestObject(payload);
    } catch (error) {
      throw new InvalidRequestObjectJwtError(
        `Invalid request object structure: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    if (isRequestObjectExpired(requestObject)) {
      throw new InvalidRequestObjectJwtError('Request object has expired');
    }

    return requestObject;
  }
}
