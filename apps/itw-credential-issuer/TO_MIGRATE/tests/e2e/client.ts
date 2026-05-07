import {
  getSignJwtCallback,
  callbacks as partialCallbacks,
} from "@/domain/crypto";
import { WalletProvider } from "@pagopa/io-wallet-oid4vci";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  addSecondsToDate,
} from "@pagopa/io-wallet-utils";
import { calculateJwkThumbprint } from "jose";

import { BASE_URL } from "./env";
import {
  accessTokenJwk,
  dpopJwk,
  dpopJwkPublic,
  requestProofJwk,
  walletProviderJwk,
  walletProviderJwkPublic,
} from "./jwk";

const TEST_JTI = "urn:ietf:params:oauth:request_uri:1234";

// ============================================================================
// Client and attestations setup
// ============================================================================

export const callbacks = {
  ...partialCallbacks,
  fetch,
  signJwt: getSignJwtCallback([
    requestProofJwk,
    dpopJwk,
    accessTokenJwk,
    walletProviderJwk,
  ]),
};

export async function createAttestations() {
  const [clientAttestationPoP, walletAttestation] = await Promise.all([
    createClientAttestationPoP(),
    createWalletAttestation(),
  ]);

  return { clientAttestationPoP, walletAttestation };
}

export const getClientId = async (): Promise<string> =>
  calculateJwkThumbprint(dpopJwkPublic);

async function createClientAttestationPoP() {
  const clientId = await getClientId();
  const jwtSigner = {
    alg: "ES256",
    kid: dpopJwkPublic.kid,
    method: "jwk",
    publicJwk: dpopJwkPublic,
  } as const;

  const { jwt } = await callbacks.signJwt(jwtSigner, {
    header: {
      alg: "ES256",
      typ: "oauth-client-attestation-pop+jwt",
    },
    payload: {
      aud: BASE_URL,
      exp: Math.floor(Date.now() / 1000) + 3600 * 24 * 60 * 60,
      iat: Math.floor(Date.now() / 1000),
      iss: clientId,
      jti: TEST_JTI,
    },
  });

  return jwt;
}

export const config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
});

export const walletProvider = new WalletProvider(config);

async function createWalletAttestation() {
  return await walletProvider.createItWalletAttestationJwt({
    authenticatorAssuranceLevel: "AAL2",
    callbacks,
    dpopJwkPublic,
    expiresAt: addSecondsToDate(new Date(), 3600 * 24 * 60 * 60),
    issuer: "https://wallet-provider.example.it",
    signer: {
      alg: "ES256",
      kid: walletProviderJwkPublic.kid,
      method: "federation",
      trustChain: [
        "eyJraWQiOiJISDlKWTl4RkEzZUJwN0d2UXNKRWZ2Z1lYekh2NGRFZThsbmt4dDB2MGNRIiwidHlwIjoiZW50aXR5LXN0YXRlbWVudCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdXRob3JpdHlfaGludHMiOltdLCJpc3MiOiJodHRwczovL3dhbGxldC1wcm92aWRlci5jb20iLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJrem91REZ6N05saEdfY1cwME1YX2U1YmZtR21NUkNINFVPeHp5MTZUcUpZIiwieCI6IjNLWlJidmdaVER0Nk5nQWJnOHpISnRqUVM2RkhENldlT0VDN1liSS1aNTQiLCJ5IjoiNU5TSFVhWWJVMjV0WHE3bUpwQ29YVUZtaU41Ykt1ZU9fNlBNc1E0cnBTSSIsImFsZyI6IkVTMjU2In1dfSwibWV0YWRhdGEiOnsiZmVkZXJhdGlvbl9lbnRpdHkiOnsiaG9tZXBhZ2VfdXJpIjoiaHR0cHM6Ly9pby5pdGFsaWEuaXQiLCJsb2dvX3VyaSI6Imh0dHBzOi8vaW8uaXRhbGlhLml0L2Fzc2V0cy9pbWcvaW8taXQtbG9nby1ibHVlLnN2ZyIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiUGFnb1BhIFMucC5BLiIsInBvbGljeV91cmkiOiJodHRwczovL2lvLml0YWxpYS5pdC9wcml2YWN5LXBvbGljeSIsInRvc191cmkiOiJodHRwczovL2lvLml0YWxpYS5pdC9wcml2YWN5LXBvbGljeSJ9LCJ3YWxsZXRfcHJvdmlkZXIiOnsiYWFsX3ZhbHVlc19zdXBwb3J0ZWQiOlsiaHR0cHM6Ly9pby1kLWl0bi1ldWRpdy1hcGktZnVuYy0wMS5henVyZXdlYnNpdGVzLm5ldC9Mb0EvYmFzaWMiLCJodHRwczovL2lvLWQtaXRuLWV1ZGl3LWFwaS1mdW5jLTAxLmF6dXJld2Vic2l0ZXMubmV0L0xvQS9tZWRpdW0iLCJodHRwczovL2lvLWQtaXRuLWV1ZGl3LWFwaS1mdW5jLTAxLmF6dXJld2Vic2l0ZXMubmV0L0xvQS9oaWdodCJdLCJncmFudF90eXBlc19zdXBwb3J0ZWQiOlsidXJuOmlldGY6cGFyYW1zOm9hdXRoOmNsaWVudC1hc3NlcnRpb24tdHlwZTpqd3QtY2xpZW50LWF0dGVzdGF0aW9uIl0sImp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJ4IjoiM0taUmJ2Z1pURHQ2TmdBYmc4ekhKdGpRUzZGSEQ2V2VPRUM3WWJJLVo1NCIsInkiOiI1TlNIVWFZYlUyNXRYcTdtSnBDb1hVRm1pTjViS3VlT182UE1zUTRycFNJIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJrem91REZ6N05saEdfY1cwME1YX2U1YmZtR21NUkNINFVPeHp5MTZUcUpZIn1dfSwidG9rZW5fZW5kcG9pbnQiOiJodHRwczovL2lvLWQtaXRuLWV1ZGl3LWFwaS1mdW5jLTAxLmF6dXJld2Vic2l0ZXMubmV0L3Rva2VuIiwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2RzX3N1cHBvcnRlZCI6WyJwcml2YXRlX2tleV9qd3QiXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19LCJhdXRob3JpemF0aW9uX2VuZHBvaW50IjoiaGFpcDovLyIsInJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZCI6WyJ2cF90b2tlbiJdLCJ2cF9mb3JtYXRzX3N1cHBvcnRlZCI6eyJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiXX19LCJjbGllbnRfaWRfc2NoZW1lc19zdXBwb3J0ZWQiOlsicHJlLXJlZ2lzdHJlZCIsIng1MDlfc2FuX2RucyJdfSwic3ViIjoiaHR0cHM6Ly93YWxsZXQtcHJvdmlkZXIuY29tIiwiaWF0IjoxNzQ3ODM4Nzc4LCJleHAiOjE3NDc5MjUxNzh9.bTMo-_ADJDgMPtIiCgv2EAWRGStOzkkQx_p8TFua4c0Enud6kDwP5vkVnWwCDa-0bm4YgTeqpswrMNrN1KmvwQ",
      ],
    },
    walletLink: "https://wallet-provider.example.it/wallet",
    walletName: "Wallet",
  });
}
