import { createHmac, randomBytes } from 'node:crypto';

import { EmbeddedJWK, SignJWT, type JWK, importJWK, jwtVerify } from 'jose';

import type { JwksRepository } from '../signer.js';
import type { MrtdAuthSession, ParRequest } from '../z-par.js';

export interface IEdocParRepository {
  getByMrtdAuthSession(mrtdAuthSessionId: string): Promise<{ parRequest: ParRequest; requestUri: string } | undefined>;
  /**
   * Atomically transitions the MRTD session to `pending_mrtd_verify` by updating the PAR entry
   * only when the session is still in `pending_mrtd_init` state and the nonce has not yet been
   * consumed. Returns `true` if the update was applied; `false` if a concurrent request already
   * claimed the session (caller should treat this as a replay and respond with 403).
   */
  atomicClaimSession(requestUri: string, mrtdAuthSessionId: string, updatedParRequest: ParRequest): Promise<boolean>;
}

export interface EdocProofInitOptions {
  readonly baseURL: string;
  readonly clientAttestationJwt: string;
  readonly clientAttestationPopJwt: string;
  readonly mrtdAuthSessionId: string;
  readonly mrtdPopJwtNonce: string;
}

export class EdocProofInitError extends Error {
  readonly statusCode: 400 | 401 | 403;

  constructor(message: string, statusCode: 400 | 401 | 403 = 400) {
    super(message);
    this.name = 'EdocProofInitError';
    this.statusCode = statusCode;
    Object.setPrototypeOf(this, EdocProofInitError.prototype);
  }
}

export class EdocProofService {
  readonly #edocParRepository: IEdocParRepository;
  readonly #jwksRepository: JwksRepository;

  constructor(edocParRepository: IEdocParRepository, jwksRepository: JwksRepository) {
    this.#edocParRepository = edocParRepository;
    this.#jwksRepository = jwksRepository;
  }

  async processInit(options: EdocProofInitOptions): Promise<string> {
    const walletPublicKey = await validateClientAttestation(
      options.clientAttestationJwt,
      options.clientAttestationPopJwt,
      options.baseURL
    );

    const result = await this.#edocParRepository.getByMrtdAuthSession(options.mrtdAuthSessionId);
    if (!result) {
      throw new EdocProofInitError('mrtd_auth_session not found');
    }

    const { requestUri, parRequest } = result;
    const session = parRequest.mrtd_auth_session;

    if (!session) {
      throw new EdocProofInitError('PAR entry does not contain an MRTD auth session');
    }

    if (Date.now() > session.expires_at) {
      throw new EdocProofInitError('MRTD auth session has expired');
    }

    if (session.status !== 'pending_mrtd_init') {
      const antiReplayStates = ['pending_mrtd_verify', 'verified', 'completed'];
      const statusCode = antiReplayStates.includes(session.status) ? 403 : 400;
      throw new EdocProofInitError(
        `MRTD auth session is not in pending_mrtd_init state (current: ${session.status})`,
        statusCode
      );
    }

    if (session.mrtd_pop_jwt_nonce !== options.mrtdPopJwtNonce) {
      throw new EdocProofInitError('mrtd_pop_jwt_nonce does not match the issued challenge');
    }

    if (session.mrtd_pop_jwt_nonce_consumed_at !== undefined) {
      throw new EdocProofInitError('mrtd_pop_jwt_nonce has already been used', 403);
    }

    // Generate 256-bit CSPRNG challenge
    const challenge = randomBytes(32).toString('base64url');

    // Derive 128-bit mrtd_pop_nonce with nonce chaining via HMAC-SHA256
    const mrtdPopNonce = deriveNewNonce(options.mrtdPopJwtNonce);

    const updatedSession: MrtdAuthSession = {
      ...session,
      challenge,
      mrtd_pop_jwt_nonce_consumed_at: Date.now(),
      mrtd_pop_nonce: mrtdPopNonce,
      status: 'pending_mrtd_verify',
      wallet_public_key: walletPublicKey as MrtdAuthSession['wallet_public_key']
    };

    const updatedParRequest = { ...parRequest, mrtd_auth_session: updatedSession };
    const claimed = await this.#edocParRepository.atomicClaimSession(
      requestUri,
      options.mrtdAuthSessionId,
      updatedParRequest as ParRequest
    );
    if (!claimed) {
      throw new EdocProofInitError('mrtd_pop_jwt_nonce has already been used', 403);
    }

    const { private: signKey, public: signPublic } = this.#jwksRepository.getSign();
    const alg = ((signKey as Record<string, unknown>)['alg'] as string | undefined) ?? 'ES256';
    const joseKey = await importJWK(signKey as JWK, alg);

    const jwt = await new SignJWT({
      aud: parRequest.client_id,
      challenge,
      htm: 'POST',
      htu: `${options.baseURL}/edoc-proof/verify`,
      mrtd_pop_nonce: mrtdPopNonce
    })
      .setProtectedHeader({ alg, kid: signPublic.kid, typ: 'mrtd-ias-pop+jwt' })
      .setIssuer(options.baseURL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(joseKey);

    return jwt;
  }
}

/**
 * Derives a 128-bit (16-byte) nonce that chains the previous nonce value via HMAC-SHA256.
 * Uses HMAC-SHA256(key=prevNonceBytes, data=32 random bytes), taking the first 16 bytes.
 */
function deriveNewNonce(previousNonce: string): string {
  const prevNonceBytes = Buffer.from(previousNonce, 'base64url');
  const randomMaterial = randomBytes(32);
  const derived = createHmac('sha256', prevNonceBytes).update(randomMaterial).digest();
  return derived.subarray(0, 16).toString('base64url');
}

/**
 * Validates OAuth-Client-Attestation and OAuth-Client-Attestation-PoP headers.
 *
 * The attestation JWT MUST carry its signing public key in the protected header's
 * `jwk` parameter (RFC 7517 §4.6 / JWS embedded key). The signature is verified
 * against that key so that self-signed forgeries cannot be used to inject an
 * arbitrary cnf.jwk. Private-key material in cnf.jwk is also rejected.
 *
 * Returns the verified wallet public JWK from `cnf.jwk` for storage in the session.
 */
async function validateClientAttestation(
  attestationJwt: string,
  attestationPopJwt: string,
  audience: string
): Promise<JWK> {
  let attestationPayload: Record<string, unknown>;

  try {
    const { payload } = await jwtVerify(attestationJwt, EmbeddedJWK, { clockTolerance: 300 });
    attestationPayload = payload as Record<string, unknown>;
  } catch {
    throw new EdocProofInitError('OAuth-Client-Attestation is not a valid JWT', 401);
  }

  const cnf = attestationPayload['cnf'] as { jwk?: JWK } | undefined;
  const walletPublicKey = cnf?.jwk;

  if (!walletPublicKey || typeof walletPublicKey !== 'object') {
    throw new EdocProofInitError('OAuth-Client-Attestation is missing cnf.jwk claim', 401);
  }

  // Reject private-key material: the 'd' parameter is present on EC and RSA private keys.
  if ('d' in walletPublicKey) {
    throw new EdocProofInitError('OAuth-Client-Attestation cnf.jwk must not contain private key material', 401);
  }

  let walletKey: Awaited<ReturnType<typeof importJWK>>;
  try {
    walletKey = await importJWK(walletPublicKey, (walletPublicKey.alg as string) ?? 'ES256');
  } catch {
    throw new EdocProofInitError('OAuth-Client-Attestation cnf.jwk is not a valid public key', 401);
  }

  try {
    await jwtVerify(attestationPopJwt, walletKey, {
      audience,
      clockTolerance: 300,
      typ: 'oauth-client-attestation-pop+jwt'
    });
  } catch {
    throw new EdocProofInitError('OAuth-Client-Attestation-PoP verification failed', 401);
  }

  return walletPublicKey;
}
