import {
  CallbackContext,
  JwtPayload,
  Oauth2Error,
  verifyTokenDPoP,
} from "@pagopa/io-wallet-oauth2";
import {
  CreateCredentialResponseResult,
  createCredentialResponse,
  parseCredentialRequest,
  verifyCredentialRequestJwtProof,
} from "@pagopa/io-wallet-oid4vci";
import {
  HttpMethod,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { decodeJwt, decodeProtectedHeader } from "jose";

import type { FakeUser } from "./faker";
import type { SupportedCredentialsId } from "./z-credential";

import { createDisabilityCardCredential } from "./credentials/disability-card";
import { createPidCredential } from "./credentials/pid";
import { generateFakeUser } from "./faker";
import { createMdocCredential, getMdocCredentialDefinition } from "./mdoc";
import { NonceRepository } from "./nonce";
import { JwksRepository } from "./signer";
import { JwkPublicKey } from "./z-jwk";

export class CreateCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CreateCredentialError";

    Object.setPrototypeOf(this, CreateCredentialError.prototype);
  }
}

export class InvalidProofError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidProofError";

    Object.setPrototypeOf(this, InvalidProofError.prototype);
  }
}

const TRUSTED_WALLET_PROVIDER_ISSUERS = [
  "https://wallet-provider.example",
  "https://wallet-provider.wct.example:3002",
];

export interface CreateCredentialOptions {
  /* * The body of the request, as a string. */
  baseURL: string;

  body: string;
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">;

  config: IoWalletSdkConfig;

  headers: Headers;
  /* The JwksRepository used to sign the access token */
  jwksRepository: JwksRepository;

  /* HTTP method of the credential request, used for DPoP htm binding */
  method: HttpMethod;

  /* The NonceRepository used to retrieve c_nonce */
  nonceRepository: NonceRepository;

  /* Full URL of the credential request, used for DPoP htu binding */
  url: string;
}
/**
 * Handles the full credential issuance process:
 *   - Validates and parses the request body
 *   - Verifies proof of possession (e.g., JWT proof)
 *   - Issues a signed SD-JWT credential to the holder
 */
export const createCredential = async (
  options: CreateCredentialOptions,
): Promise<CreateCredentialResponseResult> => {
  const { accessToken, credentialRequest, dpopProof, proofs } =
    parseCredentialRequest({
      config: options.config,
      credentialRequest: JSON.parse(options.body),
      headers: options.headers,
    });

  const headerDpopProof = decodeProtectedHeader(dpopProof);
  if (!headerDpopProof.jwk || "d" in headerDpopProof.jwk) {
    throw new CreateCredentialError(
      "Private keys are not allowed in the DPoP Proof JWT!",
    );
  }

  // Verify that the proof binding key matches the DPoP key bound to the access token
  const { cnf, sub } = decodeJwt<JwtPayload>(accessToken);

  if (!cnf.jkt) {
    throw new CreateCredentialError("Access token is missing cnf.jkt claim");
  }

  try {
    await verifyTokenDPoP({
      accessToken,
      callbacks: options.callbacks,
      dpopJwt: dpopProof,
      expectedJwkThumbprint: cnf.jkt,
      request: {
        headers: options.headers,
        method: options.method,
        url: options.url,
      },
    });
  } catch (err) {
    if (err instanceof Oauth2Error) {
      throw new InvalidProofError(err.message);
    }
    throw err;
  }

  const jwt = proofs[0].jwt;

  const { nonce } = decodeJwt(jwt);
  if (typeof nonce !== "string") {
    throw new CreateCredentialError("Missing nonce in credential request");
  }

  const expectedNonce = await options.nonceRepository.get(nonce);
  if (!expectedNonce) {
    throw new CreateCredentialError("Expected nonce not found");
  }

  // Consume the nonce immediately to prevent replay attacks with the same proof key.
  await options.nonceRepository.delete(nonce);

  const { header } = await verifyCredentialProof(options, expectedNonce, jwt);

  const holderPublicKey = JwkPublicKey.safeParse(header.jwk);
  if (!holderPublicKey.success) {
    throw new CreateCredentialError("Invalid parsing jwk!");
  }

  if (header.jwk.d) {
    throw new CreateCredentialError(
      "Private keys are not allowed in the proof JWT!",
    );
  }

  const fakeUser = generateFakeUser(sub);

  const credential = await createCredentialByConfiguration(
    credentialRequest.credential_identifier as SupportedCredentialsId,
    options.baseURL,
    options.config,
    options.jwksRepository,
    fakeUser,
    holderPublicKey.data,
  );

  const credentialResponse = await buildCredentialResponse(
    options.config,
    credential,
  );

  return credentialResponse;
};

const verifyCredentialProof = async (
  options: CreateCredentialOptions,
  expectedNonce: string,
  jwt: string,
) => {
  const config = options.config;
  const verifyCredentialProofOptions = {
    callbacks: options.callbacks,
    credentialIssuer: options.baseURL,
    expectedNonce,
    jwt,
  };

  if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
    return await verifyCredentialRequestJwtProof({
      ...verifyCredentialProofOptions,
      config,
      trustedWalletProviderIssuers: TRUSTED_WALLET_PROVIDER_ISSUERS,
    });
  }

  if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
    return await verifyCredentialRequestJwtProof({
      ...verifyCredentialProofOptions,
      config,
    });
  }

  throw new CreateCredentialError("Unsupported IT Wallet specs version");
};

const buildCredentialResponse = async (
  config: IoWalletSdkConfig,
  credential: string,
): Promise<CreateCredentialResponseResult> => {
  const flow: {
    credentials: [{ credential: string }, ...{ credential: string }[]];
  } = {
    credentials: [{ credential }],
  };

  if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
    return await createCredentialResponse({
      config,
      flow,
    });
  }

  if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
    return await createCredentialResponse({
      config,
      flow,
    });
  }

  throw new CreateCredentialError("Unsupported IT Wallet specs version");
};

/**
 * Creates a digital credential based on the provided credential configuration ID.
 *
 * @param credentialIdentifier - Identifier of the supported credential configuration type.
 * @param baseURL - Base URL used for the credential generation process.
 * @param jwksRepository - Repository used to fetch or store JSON Web Key Sets (JWKS).
 * @param holderPublicKey - The public key of the credential holder used for signing or encryption.
 * @returns credential string in sd-jwt or mdoc format
 */
const createCredentialByConfiguration = async (
  credentialIdentifier: SupportedCredentialsId,
  baseURL: string,
  config: IoWalletSdkConfig,
  jwksRepository: JwksRepository,
  fakeUser: FakeUser,
  holderPublicKey: JwkPublicKey,
): Promise<string> => {
  if (credentialIdentifier === "dc_sd_jwt_PersonIdentificationData") {
    return await createPidCredential(
      baseURL,
      jwksRepository,
      holderPublicKey,
      config,
      fakeUser,
    );
  }

  if (credentialIdentifier === "dc_sd_jwt_EuropeanDisabilityCard") {
    return await createDisabilityCardCredential(
      baseURL,
      jwksRepository,
      holderPublicKey,
      config,
      fakeUser,
    );
  }

  if (
    credentialIdentifier === "org.iso.18013.5.1.mDL" ||
    credentialIdentifier === "mso_mdoc_mDL" ||
    credentialIdentifier === "mso_mdoc_CompanyBadge" ||
    credentialIdentifier === "mso_mdoc_PersonIdentificationData"
  ) {
    const document = getMdocCredentialDefinition(
      credentialIdentifier,
      config,
      holderPublicKey,
      fakeUser,
    );

    return await createMdocCredential(
      document,
      jwksRepository,
      holderPublicKey,
    );
  }

  throw new CreateCredentialError(
    `Credential Identifier ${credentialIdentifier} not found`,
  );
};
