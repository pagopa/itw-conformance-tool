import type {
  Openid4vpAuthorizationRequestPayload,
  ParseAuthorizationResponseResult,
} from "@pagopa/io-wallet-oid4vp";
import type { JwtPayload } from "@sd-jwt/types";

import { Verifier, base64url } from "@owf/mdoc";
import { ES256, digest, generateSalt } from "@sd-jwt/crypto-nodejs";
import { decodeSdJwt } from "@sd-jwt/decode";
import {
  SDJwtVcInstance,
  VerificationResult as SDJwtVcVerificationResult,
} from "@sd-jwt/sd-jwt-vc";
import { DcqlQuery } from "dcql";

import type { JwkPublicKey } from "./z-jwk";

import { getIssuerPublicKey } from "./crypto";
import { mdocContext } from "./mdoc/context";
import { createOid4VpSessionTranscript, pemToDer } from "./mdoc/utils";

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
    options?: SDJwtVcVerifierOptions,
  ): Promise<SDJwtVcVerificationResult> {
    if (options?.verifyStatusList !== false) {
      return super.verify(encodedSDJwt, options);
    }

    const baseVerifier = Object.getPrototypeOf(
      SDJwtVcInstance.prototype,
    ) as SDJwtVcInstance;

    const result = (await baseVerifier.verify.call(
      this,
      encodedSDJwt,
      options,
    )) as SDJwtVcVerificationResult;

    if (this.userConfig.loadTypeMetadataFormat) {
      result.typeMetadata = await this.getVct(encodedSDJwt);
    }

    return result;
  }
}

interface VpTokenVerifierOptions {
  authResponse: ParseAuthorizationResponseResult;
  iacaX509: string;
  requestObject: Openid4vpAuthorizationRequestPayload;
  verifierEncryptionPublicJwk?: JwkPublicKey;
}

export class VpTokenVerifier {
  private authResponse: ParseAuthorizationResponseResult;
  private iacaX509: string;
  private requestObject: Openid4vpAuthorizationRequestPayload;
  private verifierEncryptionPublicJwk?: JwkPublicKey;

  constructor(options: VpTokenVerifierOptions) {
    this.authResponse = options.authResponse;
    this.requestObject = options.requestObject;
    this.iacaX509 = options.iacaX509;
    this.verifierEncryptionPublicJwk = options.verifierEncryptionPublicJwk;
  }

  private getHandoverUri(): string {
    const requestObject = this.requestObject as {
      redirect_uri?: string;
      response_uri?: string;
    } & Openid4vpAuthorizationRequestPayload;

    if (requestObject.redirect_uri) {
      return requestObject.redirect_uri;
    }

    if (requestObject.response_uri) {
      return requestObject.response_uri;
    }

    throw new Error(
      "OID4VP request object is missing both redirect_uri and response_uri",
    );
  }

  private normalizeCredentialTokens(
    credentialId: string,
    token: unknown,
  ): string[] {
    if (typeof token === "string") {
      return [token];
    }

    if (Array.isArray(token)) {
      if (token.length === 0) {
        throw new Error(
          `Credential token array for ID ${credentialId} is empty`,
        );
      }

      if (!token.every((value) => typeof value === "string")) {
        throw new Error(
          `Credential token array for ID ${credentialId} contains non-string values`,
        );
      }

      return token;
    }

    throw new Error(
      `Credential token for ID ${credentialId} must be a string or an array of strings`,
    );
  }

  private validateVpTokenStruct() {
    const vpToken = this.authResponse.authorizationResponsePayload.vp_token;

    if (typeof vpToken !== "object" || Array.isArray(vpToken)) {
      throw new Error("vp_token format is invalid");
    }

    const dcqlQuery = DcqlQuery.parse(
      this.requestObject.dcql_query as DcqlQuery.Input,
    );

    const dcqlCredentialsId = dcqlQuery.credentials.map((c) => c.id);
    const vpTokenCredentialsId = Object.keys(vpToken);

    const hasRequiredCredentials =
      vpTokenCredentialsId.length === dcqlCredentialsId.length &&
      vpTokenCredentialsId.every((id) => dcqlCredentialsId.includes(id));

    if (!hasRequiredCredentials) {
      throw new Error("vp_token does not contain the required credentials");
    }

    return { dcqlQuery, vpToken };
  }

  /**
   * Verifies an mDoc VP token according to ISO 18013-5 and ISO 18013-7 (OID4VP).
   * Performs issuer signature verification and device key binding verification
   * using a session transcript specific to the OID4VP flow.
   */
  private async verifyMdocToken(token: string): Promise<void> {
    const sessionTranscript = await createOid4VpSessionTranscript({
      clientId: this.requestObject.client_id,
      handoverUri: this.getHandoverUri(),
      nonce: this.authResponse.expectedNonce,
      verifierEncryptionPublicJwk: this.verifierEncryptionPublicJwk,
    });

    await Verifier.verifyDeviceResponse(
      {
        deviceResponse: base64url.decode(token),
        sessionTranscript,
        trustedCertificates: [pemToDer(this.iacaX509)],
      },
      mdocContext,
    );
  }

  /**
   * Verifies a VP token (Verifiable Presentation token) in SD-JWT-VC format.
   * This function performs the following verification steps:
   * 1. Decodes the SD-JWT token
   * 2. Extracts the holder's public key from the cnf (confirmation) claim
   * 3. Extracts the issuer's public key from the header (trust_chain or x5c)
   * 4. Verifies both the issuer's signature and the key binding
   */
  private async verifySdJwtToken(token: string) {
    const { jwt, kbJwt } = await decodeSdJwt(token, digest);
    const payload = jwt.payload as JwtPayload;
    const header = jwt.header;

    const holderPublicKey = payload.cnf?.jwk;
    if (!holderPublicKey) {
      throw new Error(
        "vp_token is missing 'jwk' in the 'cnf' (confirmation) claim",
      );
    }

    if (!header.kid || typeof header.kid !== "string") {
      throw new Error(
        "vp_token header is missing 'kid' (key identifier) or it is invalid",
      );
    }

    if (kbJwt.payload.aud !== this.requestObject.client_id) {
      throw new Error(
        "vp_token key binding 'aud' does not match the client_id in the request",
      );
    }

    if (kbJwt.header.typ !== "kb+jwt") {
      throw new Error("vp_token key binding JWT 'typ' header is not 'kb+jwt'");
    }

    // Extract issuer's public key from either trust_chain or x5c
    const issuerPublicKey = await getIssuerPublicKey(header, header.kid);

    // Create verifiers for both issuer signature and key binding
    const [issuerSignatureVerifier, keyBindingVerifier] = await Promise.all([
      ES256.getVerifier(issuerPublicKey),
      ES256.getVerifier(holderPublicKey),
    ]);

    const sdJwtVc = new LocalSDJwtVcInstance({
      hashAlg: "sha-256",
      hasher: digest,
      kbSignAlg: ES256.alg,
      kbVerifier: keyBindingVerifier,
      saltGenerator: generateSalt,
      signAlg: ES256.alg,
      verifier: issuerSignatureVerifier,
    });

    await sdJwtVc.verify(token, {
      keyBindingNonce: this.authResponse.expectedNonce,
      verifyStatusList: false,
    });
  }

  /**
   * Verifies all credentials in the vp_token according to their specified formats
   * in the DCQL query. Supports "mso_mdoc" and "dc+sd-jwt" formats.
   */
  public async verifyCredentials() {
    const { dcqlQuery, vpToken } = this.validateVpTokenStruct();
    const verifications: Promise<void>[] = [];

    for (const [credentialId, token] of Object.entries(vpToken)) {
      const credentialQuery = dcqlQuery.credentials.find(
        (c) => c.id === credentialId,
      );

      if (!credentialQuery) {
        throw new Error(
          `No matching credential query found for credential ID: ${credentialId}`,
        );
      }

      const credentialTokens = this.normalizeCredentialTokens(
        credentialId,
        token,
      );

      for (const credentialToken of credentialTokens) {
        if (credentialQuery.format === "mso_mdoc") {
          const verification = this.verifyMdocToken(credentialToken);
          verifications.push(verification);
        } else if (credentialQuery.format === "dc+sd-jwt") {
          const verification = this.verifySdJwtToken(credentialToken);
          verifications.push(verification);
        } else {
          throw new Error(
            `Unsupported credential format: ${credentialQuery.format}`,
          );
        }
      }
    }

    await Promise.all(verifications);
  }
}
