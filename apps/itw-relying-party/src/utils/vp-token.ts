import {
  type Openid4vpAuthorizationRequestPayload,
  type ParseAuthorizationResponseResult
} from '@pagopa/io-wallet-oid4vp';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { decodeSdJwt } from '@sd-jwt/decode';
import { SDJwtVcInstance, type VerificationResult as SDJwtVcVerificationResult } from '@sd-jwt/sd-jwt-vc';
import { DcqlQuery } from 'dcql';

import { trustChainToJwk } from './crypto.js';
import { getCertificateChainPublicKey } from './x509.js';

import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { JwtPayload } from '@sd-jwt/types';

export interface SDJwtVcVerifierOptions {
  [key: string]: unknown;
  keyBindingNonce?: string;
  verifyStatusList?: boolean;
}

// Extending SDJwtVcInstance to allow skipping status list verification when
// verifying VP tokens in the OID4VP flow.
export class LocalSDJwtVcInstance extends SDJwtVcInstance {
  public override async verify(
    encodedSDJwt: string,
    options?: SDJwtVcVerifierOptions
  ): Promise<SDJwtVcVerificationResult> {
    if (options?.verifyStatusList !== false) {
      return super.verify(encodedSDJwt, options);
    }

    const baseVerifier = Object.getPrototypeOf(SDJwtVcInstance.prototype) as SDJwtVcInstance;

    const result = (await baseVerifier.verify.call(this, encodedSDJwt, options)) as SDJwtVcVerificationResult;

    if (this.userConfig.loadTypeMetadataFormat) {
      result.typeMetadata = await this.getVct(encodedSDJwt);
    }

    return result;
  }
}

interface VpTokenVerifierOptions {
  authResponse: ParseAuthorizationResponseResult;
  iacaX509: string;
  /** Relying Party entity identifier, one of the two accepted key binding audiences. */
  relyingPartyEntityId: string;
  requestObject: Openid4vpAuthorizationRequestPayload;
  verifierEncryptionPublicJwk?: Jwk;
}

/**
 * Which of the two accepted forms a wallet used for the key binding `aud`.
 * IT Wallet requires the Relying Party entity identifier; OpenID4VP 1.0
 * requires the full Client Identifier including its prefix. Both are accepted,
 * and which one arrived is recorded as evidence rather than being judged here.
 */
export type KeyBindingAudienceForm = 'entity-identifier' | 'prefixed-client-id';

export interface KeyBindingAudienceRecord {
  aud: string;
  credentialId: string;
  form: KeyBindingAudienceForm;
}

export class VpTokenVerifier {
  /**
   * The key binding audience observed on each verified presentation, in the
   * order they were verified. Populated by `verifyCredentials`.
   */
  public readonly keyBindingAudiences: KeyBindingAudienceRecord[] = [];

  private authResponse: ParseAuthorizationResponseResult;
  private relyingPartyEntityId: string;
  private requestObject: Openid4vpAuthorizationRequestPayload;

  constructor(options: VpTokenVerifierOptions) {
    this.authResponse = options.authResponse;
    this.relyingPartyEntityId = options.relyingPartyEntityId;
    this.requestObject = options.requestObject;
  }

  /**
   * The key binding `aud` values this Relying Party accepts, most authoritative
   * first. IT Wallet mandates the entity identifier, so it leads; the full
   * prefixed Client Identifier follows because OpenID4VP 1.0 mandates that
   * instead, and failing an otherwise-correct wallet over which of the two
   * specs it read would be a false negative.
   */
  public get acceptedKeyBindingAudiences(): string[] {
    return [this.relyingPartyEntityId, this.requestObject.client_id];
  }

  private normalizeCredentialTokens(credentialId: string, token: unknown): string[] {
    if (typeof token === 'string') {
      return [token];
    }

    if (Array.isArray(token)) {
      if (token.length === 0) {
        throw new Error(`Credential token array for ID ${credentialId} is empty`);
      }

      if (!token.every((value) => typeof value === 'string')) {
        throw new Error(`Credential token array for ID ${credentialId} contains non-string values`);
      }

      return token;
    }

    throw new Error(`Credential token for ID ${credentialId} must be a string or an array of strings`);
  }

  private validateVpTokenStruct() {
    const vpToken = this.authResponse.authorizationResponsePayload.vp_token;

    if (typeof vpToken !== 'object' || Array.isArray(vpToken)) {
      throw new Error('vp_token format is invalid');
    }

    const dcqlQuery = DcqlQuery.parse(this.requestObject.dcql_query as DcqlQuery.Input);

    const dcqlCredentialsId = dcqlQuery.credentials.map((c) => c.id);
    const vpTokenCredentialsId = Object.keys(vpToken);

    const hasRequiredCredentials =
      vpTokenCredentialsId.length === dcqlCredentialsId.length &&
      vpTokenCredentialsId.every((id) => dcqlCredentialsId.includes(id));

    if (!hasRequiredCredentials) {
      throw new Error('vp_token does not contain the required credentials');
    }

    return { dcqlQuery, vpToken };
  }

  /**
   * Verifies a VP token (Verifiable Presentation token) in SD-JWT-VC format.
   * This function performs the following verification steps:
   * 1. Decodes the SD-JWT token
   * 2. Extracts the holder's public key from the cnf (confirmation) claim
   * 3. Extracts the issuer's public key from the header (trust_chain or x5c)
   * 4. Verifies both the issuer's signature and the key binding
   */
  private async verifySdJwtToken(credentialId: string, token: string): Promise<Record<string, unknown>> {
    const { jwt, kbJwt } = await decodeSdJwt(token, digest);
    const payload = jwt.payload as JwtPayload;
    const header = jwt.header;

    const holderPublicKey = payload.cnf?.jwk;
    if (!holderPublicKey) {
      throw new Error("vp_token is missing 'jwk' in the 'cnf' (confirmation) claim");
    }

    if (!header.kid || typeof header.kid !== 'string') {
      throw new Error("vp_token header is missing 'kid' (key identifier) or it is invalid");
    }

    if (!kbJwt) {
      throw new Error('vp_token is missing the key binding JWT');
    }

    const accepted = this.acceptedKeyBindingAudiences;
    const audience = kbJwt.payload.aud;
    if (typeof audience !== 'string' || !accepted.includes(audience)) {
      throw new Error(
        `vp_token key binding 'aud' must be the Relying Party entity identifier or the full prefixed client_id (one of ${accepted.join(', ')}), got ${String(audience)}`
      );
    }

    this.keyBindingAudiences.push({
      aud: audience,
      credentialId,
      form: audience === this.relyingPartyEntityId ? 'entity-identifier' : 'prefixed-client-id'
    });

    if (kbJwt.header.typ !== 'kb+jwt') {
      throw new Error("vp_token key binding JWT 'typ' header is not 'kb+jwt'");
    }

    // Extract issuer's public key from either trust_chain or x5c
    const issuerPublicKey = await this.getIssuerPublicKey(header, header.kid);

    // Create verifiers for both issuer signature and key binding
    const [issuerSignatureVerifier, keyBindingVerifier] = await Promise.all([
      ES256.getVerifier(issuerPublicKey),
      ES256.getVerifier(holderPublicKey)
    ]);

    const sdJwtVc = new LocalSDJwtVcInstance({
      hashAlg: 'sha-256',
      hasher: digest,
      kbSignAlg: ES256.alg,
      kbVerifier: keyBindingVerifier,
      saltGenerator: generateSalt,
      signAlg: ES256.alg,
      verifier: issuerSignatureVerifier
    });

    const verificationResult = await sdJwtVc.verify(token, {
      keyBindingNonce: this.authResponse.expectedNonce,
      verifyStatusList: false
    });

    return verificationResult.payload;
  }

  private getDisclosedClaims(
    claims: ReadonlyArray<{ path: ReadonlyArray<string | number | null> }>,
    payload: Record<string, unknown>
  ): Record<string, null | string> {
    return Object.fromEntries(
      claims.flatMap(({ path }) => {
        if (path.length !== 1 || typeof path[0] !== 'string') {
          return [];
        }

        const [claimName] = path;
        const value = payload[claimName];
        if (value === undefined) {
          return [];
        }

        return [[claimName, value === null ? null : typeof value === 'string' ? value : JSON.stringify(value)]];
      })
    );
  }

  private async getIssuerPublicKey(header: Record<string, unknown>, kid: string) {
    if (header.trust_chain && Array.isArray(header.trust_chain)) {
      return trustChainToJwk(header.trust_chain, kid);
    }

    if (header.x5c && Array.isArray(header.x5c)) {
      return await getCertificateChainPublicKey({
        alg: 'ES256',
        certificateChain: header.x5c
      });
    }

    throw new Error("header must contain either 'trust_chain' or 'x5c' for issuer verification");
  }

  /**
   * Verifies all credentials in the vp_token according to their specified formats
   * in the DCQL query and returns only the selectively disclosed requested claims.
   */
  public async verifyCredentials(): Promise<Record<string, null | string>[]> {
    const { dcqlQuery, vpToken } = this.validateVpTokenStruct();
    const verifications: Promise<Record<string, null | string>>[] = [];

    for (const [credentialId, token] of Object.entries(vpToken)) {
      const credentialQuery = dcqlQuery.credentials.find((c) => c.id === credentialId);

      if (!credentialQuery) {
        throw new Error(`No matching credential query found for credential ID: ${credentialId}`);
      }

      const credentialTokens = this.normalizeCredentialTokens(credentialId, token);

      for (const credentialToken of credentialTokens) {
        if (credentialQuery.format === 'dc+sd-jwt') {
          const verification = this.verifySdJwtToken(credentialId, credentialToken).then((payload) =>
            this.getDisclosedClaims(credentialQuery.claims ?? [], payload)
          );
          verifications.push(verification);
        } else {
          throw new Error(`Unsupported credential format: ${credentialQuery.format}`);
        }
      }
    }

    return await Promise.all(verifications);
  }
}
