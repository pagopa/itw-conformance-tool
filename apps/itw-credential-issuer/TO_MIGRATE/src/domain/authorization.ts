import { InvocationContext } from "@azure/functions";
import { TrustChain } from "@pagopa/io-wallet-oauth2";
import {
  Openid4vpAuthorizationRequestPayload,
  createAuthorizationRequest,
} from "@pagopa/io-wallet-oid4vp";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { randomBytes, randomUUID } from "crypto";

import { getSignJwtCallback } from "./crypto";
import { getDcqlQuery } from "./dcql";
import { getFederationMetadata } from "./openid-federation";
import { ParRequest } from "./z-par";

/**
 * Helper method that handles OAuth 2.0 authorization for PID issuance scenario.
 * It just creates the authorization code and redirects the Wallet
 * @param context InvocationContext used to access app dependencies and repositories
 * @param parRequest The session PAR request
 * @returns An object representing a redirect to the Wallet provided redirect URI
 */
export const handlePIDAuthorizationResponse = async (
  context: InvocationContext,
  parRequest: ParRequest,
) => {
  const code = randomUUID();
  parRequest.code = code;
  parRequest.code_expires_at = Math.floor(Date.now() / 1000) + 60;

  await context.app.repository.par.update(parRequest);
  const location = `${parRequest.redirect_uri}?code=${code}&state=${parRequest.state}&iss=${context.app.config.baseURL}`;

  // It doesn't involve in a login flow for now, so we can directly return the response
  return {
    headers: {
      Location: location,
    },
    status: 302,
  };
};

/**
 * Helper method that handles OID4VP-based authorization for EAA issuance scenario.
 * It creates an OID4VP Request Object that will start a PID presentation.
 * @param context InvocationContext used to access app dependencies and repositories
 * @param parRequest The session PAR request
 * @param request_uri The response URI for the OID4VP Presentation Response submission
 * @returns An object representing a response that contains a Request Object and starts
 *          an OID4VP PID presentation
 */
export const handleEAAAuthorizationResponse = async (
  context: InvocationContext,
  parRequest: ParRequest,
  request_uri: string,
) => {
  const jwksRepository = context.app.repository.jwks;
  const baseURL = context.app.config.baseURL;

  const authorizationSessionNonce = randomBytes(32).toString("hex");

  const { public: publicEnc } = jwksRepository.getEncrypt();

  const requestObject: Openid4vpAuthorizationRequestPayload = {
    client_id: baseURL,
    client_metadata: {
      application_type: "web",
      client_id: baseURL,
      client_name: "EAA Issuer Test App",
      encrypted_response_enc_values_supported: ["A256CBC-HS512"],
      jwks: {
        keys: [publicEnc],
      },
      logo_uri: "https://issuer.eaa.example.com/logo.png",
      request_uris: ["https://issuer.eaa.example.com/request"],
      response_uris: ["https://issuer.eaa.example.com/presentation-response"],
      vp_formats_supported: {
        "dc+sd-jwt": {
          "kb-jwt_alg_values": ["ES256"],
          "sd-jwt_alg_values": ["ES256", "ES384"],
        },
        // COSE algorithm identifiers: -9 = EdDSA, -50 = ECDSA w/ SHA-256 (Brainpool / P-256r1 variant).
        // mso_mdoc uses COSE numeric alg IDs instead of JWS string alg names.
        mso_mdoc: {
          deviceauth_alg_values: [-9, -50],
          issuerauth_alg_values: [-9, -50],
        },
      },
    },
    dcql_query: getDcqlQuery(context.app.sdkConfig),
    iss: baseURL,
    nonce: authorizationSessionNonce,
    response_mode: "direct_post.jwt",
    response_type: "vp_token",
    response_uri: baseURL + `/presentation-response?request_uri=${request_uri}`,
    state: parRequest.state,
  };

  const authorizationRequest = await createVersionedAuthorizationRequest(
    context,
    requestObject,
  );

  parRequest.oid4vpRequestObject =
    authorizationRequest.authorizationRequestPayload;

  await context.app.repository.par.update(parRequest);

  return {
    body: authorizationRequest.jar.authorizationRequestJwt,
    headers: {
      "Content-Type": "application/oauth-authz-req+jwt",
    },
    status: 200,
  };
};

async function createVersionedAuthorizationRequest(
  context: InvocationContext,
  requestObject: Openid4vpAuthorizationRequestPayload,
) {
  const baseURL = context.app.config.baseURL;
  const config = context.app.sdkConfig;
  const jwksRepository = context.app.repository.jwks;

  const { private: privateSig, public: publicSig } = jwksRepository.getSign();

  const federationMetadata = await getFederationMetadata({
    baseURL,
    config,
    jwksRepository,
  });

  const baseAuthorizationRequestOptions = {
    authorizationRequestPayload: requestObject,
    callbacks: {
      encryptJwe: context.app.callbacks.encryptJwe,
      signJwt: getSignJwtCallback([privateSig]),
    },
  };

  const baseJarOptions = {
    expiresInSeconds: 10000,
  };

  if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
    return await createAuthorizationRequest({
      ...baseAuthorizationRequestOptions,
      config,
      jar: {
        ...baseJarOptions,
        jwtSigner: {
          alg: "ES256",
          kid: publicSig.kid,
          method: "federation",
          trustChain: [federationMetadata] as TrustChain,
        },
      },
    });
  }

  if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
    return await createAuthorizationRequest({
      ...baseAuthorizationRequestOptions,
      authorizationRequestPayload: {
        ...requestObject,
        client_id: `x509_hash:${requestObject.client_id}`,
      },
      config,
      jar: {
        ...baseJarOptions,
        jwtSigner: {
          alg: "ES256",
          kid: publicSig.kid,
          method: "x5c",
          x5c: [context.app.repository.jwks.iacaX509()],
        },
      },
    });
  }
}
