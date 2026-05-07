import type {
  ItWalletAuthorizationServerMetadata,
  ItWalletCredentialIssuerMetadata,
  ItWalletEntityConfigurationClaims,
} from "@pagopa/io-wallet-oid-federation";

import { isClientAttestationSupported } from "@pagopa/io-wallet-oauth2";
import { Openid4vpAuthorizationRequestPayload } from "@pagopa/io-wallet-oid4vp";
import crypto from "crypto";
import { CompactEncrypt, decodeJwt, importJWK } from "jose";
import { expect } from "vitest";

import { callbacks, getClientId } from "./client";
import { BASE_URL } from "./env";
import {
  dpopJwk,
  dpopJwkPublic,
  requestProofJwk,
  requestProofJwkPublic,
} from "./jwk";
import { createMockedVpToken, createPidSdJwt } from "./sd-jwt";

export const PID_CREDENTIAL_ID = "dc_sd_jwt_PersonIdentificationData";

export class E2EIssuingTestFlow {
  accessToken: string;
  authorizationServerMetadata: ItWalletAuthorizationServerMetadata;
  clientAttestationPoP: string;
  code: string;
  issuerMetadata: ItWalletCredentialIssuerMetadata;
  nonce: string;
  pkceCode: string;
  redirectUri: string;
  requestObject: Openid4vpAuthorizationRequestPayload;
  requestUri: string;
  walletAttestation: string;

  async credentialRequest(credentialId: string) {
    const credentialSigner = {
      alg: "ES256",
      kid: requestProofJwk.kid,
      method: "jwk",
      publicJwk: requestProofJwkPublic,
    } as const;

    const proofJwt = await callbacks.signJwt(credentialSigner, {
      header: {
        alg: "ES256",
        jwk: requestProofJwkPublic,
        typ: "openid4vci-proof+jwt",
      },
      payload: {
        aud: BASE_URL,
        iat: Math.floor(Date.now() / 1000),
        iss: BASE_URL,
        nonce: this.nonce,
      },
    });

    const dpopSigner = {
      alg: "ES256",
      kid: dpopJwkPublic.kid,
      method: "jwk",
      publicJwk: dpopJwkPublic,
    } as const;

    const accessTokenHash = crypto
      .createHash("sha256")
      .update(Buffer.from(this.accessToken, "ascii"))
      .digest("base64url");

    const dpopProofJwt = await callbacks.signJwt(dpopSigner, {
      header: {
        alg: "ES256",
        jwk: dpopJwkPublic,
        typ: "dpop+jwt",
      },
      payload: {
        ath: accessTokenHash,
        htm: "POST",
        htu: this.issuerMetadata.credential_endpoint,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(),
      },
    });

    const credentialPayload = {
      credential_identifier: credentialId,
      proof: {
        jwt: proofJwt.jwt,
        proof_type: "jwt",
      },
    };

    const response = await fetch(this.issuerMetadata.credential_endpoint, {
      body: JSON.stringify(credentialPayload),
      headers: {
        Authorization: `DPoP ${this.accessToken}`,
        "Content-Type": "application/json",
        DPoP: dpopProofJwt.jwt,
      },
      method: "POST",
    });

    expect(response.status).toBe(200);
    const responseJson = await response.json();
    expect(responseJson).toHaveProperty("credentials");

    return responseJson.credentials[0].credential;
  }

  async fetchFederationMetadata() {
    const response = await fetch(`${BASE_URL}/.well-known/openid-federation`, {
      method: "GET",
    });

    expect(response.status).toBe(200);
    const responseText = await response.text();

    const { metadata } =
      decodeJwt<ItWalletEntityConfigurationClaims>(responseText);
    expect(metadata).not.toBeUndefined();

    const isSupported = isClientAttestationSupported({
      authorizationServerMetadata:
        metadata.oauth_authorization_server as ItWalletAuthorizationServerMetadata,
    });

    expect(isSupported).toEqual({ supported: true });

    this.authorizationServerMetadata =
      metadata.oauth_authorization_server as ItWalletAuthorizationServerMetadata;
    this.issuerMetadata =
      metadata.openid_credential_issuer as ItWalletCredentialIssuerMetadata;
  }

  async fetchNonce() {
    const response = await fetch(this.issuerMetadata.nonce_endpoint, {
      method: "POST",
    });

    expect(response.status).toBe(200);
    const responseJson = await response.json();
    expect(responseJson).toHaveProperty("c_nonce");

    this.nonce = responseJson.c_nonce;
  }

  async getFormPostJwt() {
    const response = await fetch(this.redirectUri, {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
      },
    });

    const html = await response.text();

    expect(response.status).toBe(200);
    expect(html).toContain("<form");

    const jwt = html.split('name="response" value="')[1].split('"')[0];

    const decodedJwt = decodeJwt<{ code: string; state?: string }>(jwt);
    expect(decodedJwt.code).toBeDefined();

    this.code = decodedJwt.code;
  }

  async openid4vciAuthzRequest() {
    const clientId = await getClientId();
    const response = await fetch(
      `${this.authorizationServerMetadata.authorization_endpoint}?client_id=${clientId}&request_uri=${this.requestUri}`,
      {
        method: "GET",
        redirect: "manual",
      },
    );

    expect(response.status).toBe(302);

    const locationUri = response.headers.get("location");
    expect(locationUri).not.toBeNull();

    const url = new URL(locationUri);
    this.code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    expect(this.code).not.toBeNull();
    expect(state).toBe("teststate123");
  }

  async openid4vpAuthzRequest() {
    const clientId = await getClientId();
    const response = await fetch(
      `${this.authorizationServerMetadata.authorization_endpoint}?client_id=${clientId}&request_uri=${this.requestUri}`,
      {
        method: "GET",
      },
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain(
      "application/oauth-authz-req+jwt",
    );

    const authorizationRequestJwt = await response.text();
    this.requestObject = decodeJwt<Openid4vpAuthorizationRequestPayload>(
      authorizationRequestJwt,
    );

    const expectedResponseUri = `${BASE_URL}/presentation-response?request_uri=${this.requestUri}`;

    expect(this.requestObject.response_uri).toBe(expectedResponseUri);
    expect(this.requestObject.response_type).toBe("vp_token");
    expect(this.requestObject.response_mode).toBe("direct_post.jwt");
    expect(this.requestObject.state).toBe("teststate123");
    expect(this.requestObject.nonce).toBeDefined();
    expect(this.requestObject.dcql_query).toBeDefined();
  }

  async presentationResponse() {
    const { client_id, client_metadata, nonce, state } = this.requestObject;

    // Initialize the SD-JWT mocks with trust chains
    const pidSdJwt = await createPidSdJwt();

    const pidVpToken = await createMockedVpToken(
      pidSdJwt.payload,
      pidSdJwt.header,
      nonce,
      client_id,
    );

    // Get the encryption key from the authorization request's client_metadata
    const encryptionKey = client_metadata.jwks.keys[0];
    expect(encryptionKey).toBeDefined();

    const responsePayload = JSON.stringify({
      state,
      vp_token: {
        "0": pidVpToken,
      },
    });

    const alg = "ECDH-ES";
    const enc = "A256CBC-HS512";
    const key = await importJWK(encryptionKey, alg);

    const plaintext = new TextEncoder().encode(responsePayload);
    const jwe = await new CompactEncrypt(plaintext)
      .setProtectedHeader({
        alg,
        enc,
        kid: encryptionKey.kid,
      })
      .encrypt(key);

    const formData = new URLSearchParams();
    formData.append("response", jwe);

    const response = await fetch(
      `${BASE_URL}/presentation-response?request_uri=${this.requestUri}`,
      {
        body: formData,
        method: "POST",
      },
    );

    expect(response.status).toBe(200);

    const responseJson = await response.json();
    expect(responseJson).toHaveProperty("redirect_uri");

    this.redirectUri = responseJson.redirect_uri;
  }

  async pushedAuthorizationRequest(credentialConfigurationId: string) {
    const clientId = await getClientId();
    this.pkceCode = "samplecodechallenge";
    const code_challenge_method = "S256";
    const code_challenge = crypto
      .createHash("sha256")
      .update(this.pkceCode)
      .digest("base64url");

    const jwtSigner = {
      alg: "ES256",
      kid: dpopJwkPublic.kid,
      method: "jwk",
      publicJwk: dpopJwkPublic,
    } as const;

    const parPayload = {
      authorization_details: [
        {
          credential_configuration_id: credentialConfigurationId,
          type: "openid_credential",
        },
      ],
      client_id: clientId,
      code_challenge,
      code_challenge_method,
      nonce: "randomnoncevalue",
      redirect_uri: "https://your-redirect-uri.com/cb",
      response_mode: "query",
      response_type: "code",
      state: "teststate123",
    };

    const requestJwt = await callbacks.signJwt(jwtSigner, {
      header: {
        alg: "ES256",
        kid: dpopJwk.kid,
        typ: "oauth-authz-req+jwt",
      },
      payload: {
        aud: BASE_URL,
        exp: Math.floor(Date.now() / 1000) + 3600 * 24 * 60 * 60,
        iat: Math.floor(Date.now() / 1000),
        iss: clientId,
        jti: crypto.randomUUID(),
        ...parPayload,
      },
    });

    const parSignedPayload = {
      client_id: clientId,
      request: requestJwt.jwt,
    };

    const response = await fetch(
      this.authorizationServerMetadata.pushed_authorization_request_endpoint,
      {
        body: new URLSearchParams(parSignedPayload),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "OAuth-Client-Attestation": this.walletAttestation,
          "OAuth-Client-Attestation-PoP": this.clientAttestationPoP,
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(201);
    const responseJson = await response.json();
    expect(responseJson).toHaveProperty("request_uri");
    expect(responseJson).toHaveProperty("expires_in");

    this.requestUri = responseJson.request_uri;
  }

  async tokenRequest() {
    const jwtSigner = {
      alg: "ES256",
      kid: dpopJwkPublic.kid,
      method: "jwk",
      publicJwk: dpopJwkPublic,
    } as const;

    const dProofJwt = await callbacks.signJwt(jwtSigner, {
      header: {
        alg: "ES256",
        jwk: dpopJwkPublic,
        typ: "dpop+jwt",
      },
      payload: {
        htm: "POST",
        htu: this.authorizationServerMetadata.token_endpoint,
        iat: Math.floor(Date.now() / 1000),
        jti: this.requestUri,
      },
    });

    const tokenPayload = {
      code: this.code,
      code_verifier: this.pkceCode,
      grant_type: "authorization_code",
      redirect_uri: "https://your-redirect-uri.com/cb",
    };

    const response = await fetch(
      this.authorizationServerMetadata.token_endpoint,
      {
        body: new URLSearchParams(tokenPayload),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          DPoP: dProofJwt.jwt,
          "OAuth-Client-Attestation": this.walletAttestation,
          "OAuth-Client-Attestation-PoP": this.clientAttestationPoP,
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(200);
    const responseJson = await response.json();
    expect(responseJson).toHaveProperty("access_token");
    expect(responseJson).toHaveProperty("authorization_details");

    this.accessToken = responseJson.access_token;
  }

  withClientAttestationPoP(clientAttestationPoP: string) {
    this.clientAttestationPoP = clientAttestationPoP;
    return this;
  }

  withWalletAttestation(walletAttestation: string) {
    this.walletAttestation = walletAttestation;
    return this;
  }
}
