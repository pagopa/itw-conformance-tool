import { appContext } from "@/app/context";
import { STATUS_LIST_URI } from "@/domain/utils/status-list";
import { JWTHeaderParameters, JWTPayload, SignJWT, importJWK } from "jose";
import crypto from "node:crypto";

import { BASE_URL } from "./env";
import { dpopJwk, dpopJwkPublic, walletProviderJwkPublic } from "./jwk";

export async function createPidSdJwt() {
  return {
    header: {
      alg: "ES256" as const,
      kid: walletProviderJwkPublic.kid,
      typ: "dc+sd-jwt",
      x5c: [appContext.repository.jwks.iacaX509()],
    },
    payload: {
      _sd: [
        "0q1D5Jmav6pQaEh_J_Fcv_uNNMQIgCyhQOxqlY4l3qU",
        "KCJ-AVNv88d-xj6sUIAOJxFnbUh3rHXDKkIH1lFqbRs",
        "M9lo9YxDNIXrAq2qWeiCA40zpJ_zYfFdR_4AEALcRtU",
        "czgjUk0nqRCswShChCjdS6A1-v47d_qTCSFIvIHhMoI",
        "nGnQr7clm3tfTp8yjL_uHrDSOtzR2PVb8S7GeLdAqBQ",
        "xNIVwlpSsaZ8CJSf0gz5x_75VRWWc6V1mlpejdCrqUs",
      ],
      _sd_alg: "sha-256",
      cnf: {
        jwk: dpopJwkPublic,
      },
      exp: 1751546576,
      iss: BASE_URL,
      issuing_authority: "PagoPA S.p.A.",
      issuing_country: "IT",
      status: {
        status_assertion: {
          credential_hash_alg: "sha-256",
        },
        status_list: {
          idx: 1,
          uri: STATUS_LIST_URI(BASE_URL),
        },
      },
      sub: "216f8946-9ecb-4819-9309-c076f34a7e11",
      vct: "PersonIdentificationData",
      "vct#integrity":
        "13e25888ac7b8a3a6d61440da787fccc81654e61085732bcacd89b36aec32675",
    },
  };
}

type CreateMockedVpToken = (
  payload: JWTPayload,
  header: JWTHeaderParameters,
  nonce: string,
  client_id: string,
) => Promise<string>;

export const createMockedVpToken: CreateMockedVpToken = async (
  payload,
  header,
  nonce,
  client_id,
) => {
  const privateKey = await importJWK(
    appContext.repository.jwks.getSign().private,
    "ES256",
  );

  // Mock issuer-signed PID token (SD-JWT)
  const sdJwt = await new SignJWT(payload)
    .setProtectedHeader(header)
    .setIssuedAt()
    .setExpirationTime("24h")
    .sign(privateKey);

  const sd_hash = crypto
    .createHash("sha256")
    .update(`${sdJwt}~`)
    .digest("base64url");

  // Use dpop key for the key binding JWT (wallet holder's key)
  const dpopPrivateKey = await importJWK(dpopJwk, "ES256");
  const kbJwt = await new SignJWT({
    iss: BASE_URL,
    nonce,
    sd_hash,
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "kb+jwt",
    })
    .setAudience(client_id)
    .setIssuedAt()
    .sign(dpopPrivateKey);

  // <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>
  const vp_token = [sdJwt, kbJwt].join("~");

  return vp_token;
};
