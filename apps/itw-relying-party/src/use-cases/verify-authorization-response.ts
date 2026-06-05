import { createHash, randomBytes } from 'node:crypto';

import { verifyJarmAuthorizationResponse } from '@pagopa/io-wallet-oid4vp';
import { compactDecrypt, importPKCS8, importJWK, jwtVerify, type JWK } from 'jose';

import { createDecryptJweCallback, createVerifyJwtCallback } from '../crypto/callbacks.js';

import type { INonceRepository } from '@itw-conformance-tool/database';
import type { PresentationValues, SessionService } from '@itw-conformance-tool/rp';
import type { Openid4vpAuthorizationRequestPayload } from '@pagopa/io-wallet-oid4vp';

const PREVIEW_PAYLOAD_SCHEMA = {
  state: 'state',
  vp_token: 'vp_token'
} as const;

export interface VerifyAuthorizationResponseInput {
  baseUrl: string;
  jarmResponse: string;
  nonceRepository: INonceRepository;
  privateKeyPem: string;
  sessionService: SessionService;
}

export interface VerifyAuthorizationResponseResult {
  redirectUri: string;
}

export class VerifyAuthorizationResponseError extends Error {
  readonly statusCode = 400;

  constructor(message: string) {
    super(message);
    this.name = 'VerifyAuthorizationResponseError';
  }
}

export class VerifyAuthorizationSessionNotFoundError extends Error {
  readonly statusCode = 404;

  constructor() {
    super('Session not found');
    this.name = 'VerifyAuthorizationSessionNotFoundError';
  }
}

function decodeDisclosureValues(vpToken: Record<string, string>): PresentationValues {
  const values: PresentationValues = [];

  for (const sdJwt of Object.values(vpToken)) {
    const disclosures = sdJwt.split('~').slice(1, -1);
    const parsedClaims: Record<string, string | null> = {};
    for (const disclosure of disclosures) {
      try {
        const decoded = JSON.parse(Buffer.from(disclosure, 'base64url').toString('utf8')) as unknown;
        if (Array.isArray(decoded) && decoded.length >= 3 && typeof decoded[1] === 'string') {
          parsedClaims[decoded[1]] = decoded[2] === null || decoded[2] === undefined ? null : String(decoded[2]);
        }
      } catch {
        // Ignore malformed disclosure entries.
      }
    }
    if (Object.keys(parsedClaims).length > 0) {
      values.push(parsedClaims);
    }
  }

  return values;
}

async function verifyAndExtractKbJwtNonce(kbJwt: string, sdJwt: string, expectedAudience?: string): Promise<string> {
  const kbJwtSegments = kbJwt.split('.');
  if (kbJwtSegments.length !== 3) {
    throw new VerifyAuthorizationResponseError('KB-JWT must be a compact JWT with exactly 3 segments');
  }

  const [headerSegment] = kbJwtSegments;
  let header: { jwk?: JWK };
  try {
    header = JSON.parse(Buffer.from(headerSegment, 'base64url').toString('utf8')) as { jwk?: JWK };
  } catch {
    throw new VerifyAuthorizationResponseError('KB-JWT header is not valid JSON');
  }

  if (!header.jwk) {
    throw new VerifyAuthorizationResponseError('KB-JWT header missing required "jwk" claim');
  }

  const holderPublicKey = await importJWK(header.jwk);

  const payload = await jwtVerify(kbJwt, holderPublicKey, { clockTolerance: 300 });
  const claims = payload.payload as Record<string, unknown>;

  if (typeof claims.nonce !== 'string') {
    throw new VerifyAuthorizationResponseError('KB-JWT missing required "nonce" claim');
  }

  if (typeof claims.sd_hash !== 'string') {
    throw new VerifyAuthorizationResponseError('KB-JWT missing required "sd_hash" claim');
  }

  if (expectedAudience) {
    if (typeof claims.aud === 'string') {
      if (claims.aud.length === 0) {
        throw new VerifyAuthorizationResponseError('KB-JWT missing required "aud" claim');
      }
      if (claims.aud !== expectedAudience) {
        throw new VerifyAuthorizationResponseError(
          `KB-JWT audience mismatch: expected "${expectedAudience}", got "${claims.aud}"`
        );
      }
    } else if (Array.isArray(claims.aud)) {
      if (claims.aud.length === 0 || claims.aud.some((aud) => typeof aud !== 'string')) {
        throw new VerifyAuthorizationResponseError('KB-JWT missing required "aud" claim');
      }
      if (!claims.aud.includes(expectedAudience)) {
        throw new VerifyAuthorizationResponseError(`KB-JWT audience does not include "${expectedAudience}"`);
      }
    } else {
      throw new VerifyAuthorizationResponseError('KB-JWT missing required "aud" claim');
    }
  }

  const disclosures = sdJwt.split('~').slice(1, -1).join('~');
  const expectedSdHash = Buffer.from(createHash('sha256').update(disclosures).digest()).toString('base64url');
  if (claims.sd_hash !== expectedSdHash) {
    throw new VerifyAuthorizationResponseError('KB-JWT sd_hash does not match SD-JWT disclosures');
  }

  return claims.nonce;
}

async function decryptForStatePreview(response: string, keyPem: string): Promise<string> {
  try {
    const privateKey = await importPKCS8(keyPem, 'ECDH-ES');
    const { plaintext } = await compactDecrypt(response, privateKey);
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
    const stateValue = payload[PREVIEW_PAYLOAD_SCHEMA.state];

    if (typeof stateValue === 'string') {
      return stateValue;
    }

    throw new VerifyAuthorizationResponseError('JARM response payload is missing state');
  } catch (error) {
    if (error instanceof VerifyAuthorizationResponseError) {
      throw error;
    }
    throw new VerifyAuthorizationResponseError('Unable to decrypt authorization response');
  }
}

function decodeAuthorizationRequestPayload(jwt: string): Openid4vpAuthorizationRequestPayload {
  const segments = jwt.split('.');
  if (segments.length !== 3) {
    throw new VerifyAuthorizationResponseError('Stored request JWT is malformed');
  }

  try {
    return JSON.parse(Buffer.from(segments[1], 'base64url').toString('utf8')) as Openid4vpAuthorizationRequestPayload;
  } catch {
    throw new VerifyAuthorizationResponseError('Unable to decode stored request JWT payload');
  }
}

function extractVpTokenAndState(payload: unknown): { state: string; vpToken: Record<string, string> } {
  if (!payload || typeof payload !== 'object') {
    throw new VerifyAuthorizationResponseError('JARM response payload is not an object');
  }

  const objectPayload = payload as Record<string, unknown>;
  const state = objectPayload.state;
  const vpToken = objectPayload.vp_token;

  if (typeof state !== 'string') {
    throw new VerifyAuthorizationResponseError('JARM response payload is missing state');
  }
  if (!vpToken || typeof vpToken !== 'object') {
    throw new VerifyAuthorizationResponseError('JARM response payload is missing vp_token');
  }

  const tokenEntries = Object.entries(vpToken as Record<string, unknown>);
  if (tokenEntries.length === 0 || tokenEntries.some(([, value]) => typeof value !== 'string')) {
    throw new VerifyAuthorizationResponseError('JARM vp_token must contain at least one string credential');
  }

  return { state, vpToken: vpToken as Record<string, string> };
}

export async function verifyAuthorizationResponseUseCase(
  input: VerifyAuthorizationResponseInput
): Promise<VerifyAuthorizationResponseResult> {
  const previewState = await decryptForStatePreview(input.jarmResponse, input.privateKeyPem);
  const session = await input.sessionService.get(previewState);

  if (!session) {
    throw new VerifyAuthorizationSessionNotFoundError();
  }

  if (session.state !== 'checking') {
    await input.sessionService.update(previewState, 'rejected');
    throw new VerifyAuthorizationResponseError('Session is not in checking state');
  }

  try {
    const authorizationRequestPayload = decodeAuthorizationRequestPayload(session.jwt);
    const expectedAudience = authorizationRequestPayload.client_id;
    const expectedNonce = authorizationRequestPayload.nonce;

    if (typeof expectedAudience !== 'string' || expectedAudience.length === 0) {
      throw new VerifyAuthorizationResponseError('Stored request JWT payload is missing client_id');
    }
    if (typeof expectedNonce !== 'string' || expectedNonce.length === 0) {
      throw new VerifyAuthorizationResponseError('Stored request JWT payload is missing nonce');
    }

    const verified = await verifyJarmAuthorizationResponse({
      authorizationRequestPayload,
      callbacks: {
        decryptJwe: createDecryptJweCallback(input.privateKeyPem),
        verifyJwt: createVerifyJwtCallback()
      },
      jarmAuthorizationResponseJwt: input.jarmResponse
    });

    const { state, vpToken } = extractVpTokenAndState(verified.jarmAuthorizationResponse);
    if (state !== previewState) {
      throw new VerifyAuthorizationResponseError('JARM state mismatch');
    }

    const verifiedNonces: string[] = [];
    for (const [credentialName, sdJwt] of Object.entries(vpToken)) {
      const parts = sdJwt.split('~');
      const kbJwt = parts[parts.length - 1];

      try {
        const nonce = await verifyAndExtractKbJwtNonce(kbJwt, sdJwt, expectedAudience);
        verifiedNonces.push(nonce);
      } catch (error) {
        throw new VerifyAuthorizationResponseError(
          `KB-JWT verification failed for credential "${credentialName}": ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }

    if (verifiedNonces.length === 0) {
      throw new VerifyAuthorizationResponseError('No key-binding nonce found in presented credentials');
    }

    const firstNonce = verifiedNonces[0];
    if (!verifiedNonces.every((nonce) => nonce === firstNonce)) {
      throw new VerifyAuthorizationResponseError('Nonce mismatch across credentials');
    }

    if (firstNonce !== expectedNonce) {
      throw new VerifyAuthorizationResponseError(
        'The nonce does not match with the one provided in the request object'
      );
    }

    const consumed = await input.nonceRepository.consume(expectedNonce);
    if (!consumed) {
      throw new VerifyAuthorizationResponseError(
        'The nonce does not match with the one provided in the request object'
      );
    }

    const values = decodeDisclosureValues(vpToken);
    const responseCode = randomBytes(32).toString('hex');
    const redirectUri = `${input.baseUrl}/success.html?response_code=${responseCode}`;

    await input.sessionService.update(state, 'verified', {
      redirectUri,
      values
    });

    return {
      redirectUri
    };
  } catch (error) {
    await input.sessionService.update(previewState, 'rejected');

    if (error instanceof VerifyAuthorizationResponseError) {
      throw error;
    }
    throw new VerifyAuthorizationResponseError(
      error instanceof Error ? error.message : 'Authorization response verification failed'
    );
  }
}
