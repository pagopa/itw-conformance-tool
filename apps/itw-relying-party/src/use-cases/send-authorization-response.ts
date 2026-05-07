import { Config } from "@/config";
import { BadRequestError, ForbiddenError, NotFoundError } from "@/errors";
import { NonceRepository, getNonce } from "@/nonce";
import {
  RequestObject,
  RequestObjectRepository,
  getRequestObject,
  markRequestObjectAsDenied,
  markRequestObjectAsVerified,
} from "@/request-object";
import {
  ClaimsObject,
  CryptographicAlgorithms,
  DcqlPresentation,
  Disclosure,
  IssuerEC,
  IssuerSignedJwtPayload,
  KbJwtPayload,
  WalletProviderEC,
} from "@/schemas";
import * as crypto from "crypto";
import { DcqlQuery } from "dcql";
import { DcqlPresentationResult } from "dcql";
import { compactDecrypt, importPKCS8 } from "jose";
import jwt from "jsonwebtoken";
import jwkToPem, { JWK } from "jwk-to-pem";
import * as z from "zod";

// 1)
async function decryptAndVerifyJWE(jwe: string, privateKeyBase64: string) {
  const privateKeyPem = Buffer.from(privateKeyBase64, "base64").toString();
  const privateKey = await importPKCS8(privateKeyPem, "ECDH-ES");
  const { plaintext } = await compactDecrypt(jwe, privateKey);
  return new TextDecoder().decode(plaintext);
}

function verifyAuthorizationResponse(
  authorizationResponse: string,
): (
  privateKeyBase64: string,
) => Promise<{ state: string; vpToken: Record<string, string> }> {
  return async function (privateKeyBase64) {
    try {
      const decryptedAuthorizationToken = await decryptAndVerifyJWE(
        authorizationResponse,
        privateKeyBase64,
      );

      if (!decryptedAuthorizationToken) {
        throw new Error();
      }

      return z
        .object({
          state: z.string(),
          vp_token: z.record(z.string()),
        })
        .transform(({ state, vp_token }) => ({
          state,
          vpToken: vp_token,
        }))
        .parse(JSON.parse(decryptedAuthorizationToken));
    } catch {
      throw new BadRequestError(
        "The response cannot be processed because cannot be decrypted or is malformed",
      );
    }
  };
}

// 2)
function verifyWalletAttestation({
  disclosures,
  issuerJwt,
  kbJwt,
}: {
  disclosures: string[];
  issuerJwt: string;
  kbJwt: string;
}): (clientId: string) => Promise<void> {
  return async function (clientId) {
    try {
      const decodedWalletAttestation = jwt.decode(issuerJwt, {
        complete: true,
      });

      if (!decodedWalletAttestation) {
        throw new BadRequestError("Wallet Attestation payload is not valid");
      }

      const {
        header: headerWalletAttestation,
        payload: payloadWalletAttestation,
      } = decodedWalletAttestation;

      if (typeof payloadWalletAttestation === "string") {
        throw new BadRequestError("Wallet Attestation payload is not valid");
      }
      const kid = headerWalletAttestation.kid;
      const iss = payloadWalletAttestation.iss;
      if (!kid) {
        throw new BadRequestError("Wallet Attestation header is not valid");
      }
      if (!iss) {
        throw new BadRequestError("Wallet Attestation payload is not valid");
      }
      const result = await fetch(`${iss}/.well-known/openid-federation`);
      const resultBody = await result.text();
      const decodedWalletProviderEC = jwt.decode(resultBody);
      const parsedWalletProviderEC = WalletProviderEC.safeParse(
        decodedWalletProviderEC,
      );
      if (parsedWalletProviderEC.error) {
        throw new Error();
      }
      const walletProviderKeys =
        parsedWalletProviderEC.data.metadata.wallet_provider.jwks.keys;
      const walletProviderKey = walletProviderKeys.find(
        (key) => key.kid === kid,
      );
      if (!walletProviderKey) {
        throw new BadRequestError("Wallet Attestation signature is not valid");
      }
      const walletProviderKeyPem = jwkToPem({
        crv: "P-256",
        kty: "EC",
        x: walletProviderKey.x,
        y: walletProviderKey.y,
      });
      jwt.verify(issuerJwt, walletProviderKeyPem);

      const {
        _sd,
        cnf: { jwk },
      } = payloadWalletAttestation;

      let holderPublicKeyPem: string;
      try {
        holderPublicKeyPem = jwkToPem(jwk);
      } catch {
        throw new ForbiddenError(
          "The public key in the issuer signed JWT is malformed",
        );
      }
      const decodedKbJwt = await verifyKbJwt(
        kbJwt,
        holderPublicKeyPem,
      )(clientId);

      const disclosuresBase64Url = disclosures.map(base64ToBase64Url);

      verifyDisclosuresSdMatch(disclosuresBase64Url, _sd);

      verifySdHash({
        disclosures: disclosuresBase64Url,
        issuerJwt,
        sdHash: decodedKbJwt.sd_hash,
      });
    } catch {
      throw new ForbiddenError(
        "Trust could not be established with the Wallet Provider",
      );
    }
  };
}

// 3)
async function getIssuerECFromFetch(
  issuer: string,
): Promise<null | z.infer<typeof IssuerEC>> {
  try {
    const result = await fetch(`${issuer}/.well-known/openid-federation`);
    if (!result.ok) {
      return null;
    }
    const resultBody = await result.text();
    const decodedIssuerEC = jwt.decode(resultBody);
    const parsedIssuerEC = IssuerEC.safeParse(decodedIssuerEC);
    if (parsedIssuerEC.error) {
      return null;
    }
    return parsedIssuerEC.data;
  } catch {
    return null;
  }
}

function getIssuerECFromTrustChain(
  issuerSignedJwt: string,
  issuer: string,
): null | z.infer<typeof IssuerEC> {
  try {
    const decodedJwt = jwt.decode(issuerSignedJwt, { complete: true });
    if (!decodedJwt) {
      return null;
    }

    const trustChain = decodedJwt.header.trust_chain;
    if (!Array.isArray(trustChain) || trustChain.length === 0) {
      return null;
    }

    // The first element in the trust_chain is typically the Entity Configuration (EC) of the issuer
    for (const entityStatement of trustChain) {
      const decodedStatement = jwt.decode(entityStatement);
      if (!decodedStatement || typeof decodedStatement === "string") {
        continue;
      }

      // Check if this statement belongs to the issuer
      if (decodedStatement.sub === issuer || decodedStatement.iss === issuer) {
        const parsedIssuerEC = IssuerEC.safeParse(decodedStatement);
        if (!parsedIssuerEC.error) {
          return parsedIssuerEC.data;
        }
      }
    }

    return null;
  } catch {
    return null;
  }
}

const verifyIssuerSignedJwt: (
  issuerSignedJwt: string,
) => Promise<IssuerSignedJwtPayload> = async (issuerSignedJwt) => {
  const issuerJwt = jwt.decode(issuerSignedJwt);
  const parsedIssuerJwt = IssuerSignedJwtPayload.safeParse(issuerJwt);
  if (parsedIssuerJwt.error) {
    throw new BadRequestError("Credentials presented are malformed");
  }
  const issuerSignedJwtPayload = parsedIssuerJwt.data;
  const issuer = issuerSignedJwtPayload.iss;

  try {
    // First, try to fetch from well-known endpoint
    let issuerEC = await getIssuerECFromFetch(issuer);

    // If fetch fails, fallback to trust_chain from the JWT header
    if (!issuerEC) {
      // eslint-disable-next-line no-console
      console.log(
        `Fetch from ${issuer}/.well-known/openid-federation failed, falling back to trust_chain`,
      );
      issuerEC = getIssuerECFromTrustChain(issuerSignedJwt, issuer);
    }

    if (!issuerEC) {
      throw new Error("Could not retrieve Issuer EC from fetch or trust_chain");
    }

    // I assume there is only one
    const issuerKey = issuerEC.metadata.openid_credential_issuer.jwks.keys[0];
    const issuerPublicKeyPem = jwkToPem({
      crv: "P-256",
      kty: "EC",
      x: issuerKey.x,
      y: issuerKey.y,
    });
    jwt.verify(issuerSignedJwt, issuerPublicKeyPem);
    return issuerSignedJwtPayload;
  } catch {
    throw new ForbiddenError(
      "Trust could not be established with the Credential Issuer",
    );
  }
};

// 4) also validations on the token itself not just the signature
function verifyKbJwt(
  kbJwt: string,
  holderKey: string,
): (clientId: string) => Promise<KbJwtPayload> {
  return async function (clientId) {
    try {
      const decodedKbJwt = jwt.verify(kbJwt, holderKey, {
        complete: true,
      });

      const { header, payload } = decodedKbJwt;

      if (header.typ !== "kb+jwt") {
        throw new BadRequestError(
          "`typ` value in KB-JWT is not correct. It must be `kb+jwt`",
        );
      }

      const parsedAlg = CryptographicAlgorithms.safeParse(header.alg);
      if (parsedAlg.error) {
        throw new BadRequestError(
          "`alg` value in KB-JWT is not correct. It must be one of the supported algorithms",
        );
      }

      if (typeof payload === "string") {
        throw new BadRequestError("Invalid KB-JWT");
      }

      const parsedPayload = KbJwtPayload.safeParse(payload);
      if (parsedPayload.error) {
        throw new BadRequestError(
          "Invalid KB-JWT: missing required claims in the payload",
        );
      }

      const kbJwtPayload = parsedPayload.data;

      if (kbJwtPayload.aud !== clientId) {
        throw new BadRequestError(
          "Invalid KB-JWT: `aud` does not match RP entity identifier",
        );
      }

      return kbJwtPayload;
    } catch (error) {
      throw error instanceof BadRequestError
        ? error
        : new ForbiddenError("The signature of KB-JWT is invalid");
    }
  };
}

function base64ToBase64Url(base64String: string) {
  return base64String
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// 5)
const verifyDisclosuresSdMatch: (
  disclosures: string[],
  issuerJwtSd: string[],
) => void = (disclosures, issuerJwtSd) => {
  try {
    const areValidDisclosures = disclosures.every((disclosure) => {
      const base64urlDisclosureHash = crypto
        .createHash("sha256")
        .update(disclosure)
        .digest("base64url");

      return issuerJwtSd.includes(base64urlDisclosureHash);
    });
    if (!areValidDisclosures) {
      throw new BadRequestError(
        "The sd-jwt returned is malformed: disclosures are wrong",
      );
    }
  } catch (error) {
    throw error instanceof BadRequestError
      ? error
      : new BadRequestError(
          "The sd-jwt returned is malformed: disclosures can not be verified",
        );
  }
};

// 6)
const verifySdHash: (params: {
  disclosures: string[];
  issuerJwt: string;
  sdHash: string;
}) => void = ({ disclosures, issuerJwt, sdHash }) => {
  try {
    const sdString = `${issuerJwt}~${disclosures.join("~")}~`;
    // TODO: check _sd_alg instead of "sha256"
    const isValidSdHash =
      crypto.createHash("sha256").update(sdString).digest("base64url") ===
      sdHash;
    if (!isValidSdHash) {
      throw new BadRequestError(
        "The sd-jwt returned is malformed: sd hash in KB-JWT is not correct",
      );
    }
  } catch (error) {
    throw error instanceof BadRequestError
      ? error
      : new BadRequestError(
          "The sd-jwt returned is malformed: sd hash can not be verified",
        );
  }
};

// 3) / 4) / 5) / 6)
// I verify the sdjwt; if it passes validation => I store it in dcqlPresentation and save the nonce in nonces

function verifyIssuerCredentialJwt({
  disclosures,
  issuerJwt,
  kbJwt,
}: {
  disclosures: string[];
  issuerJwt: string;
  kbJwt: string;
}): (clientId: string) => Promise<void> {
  return async function (clientId) {
    const {
      _sd,
      cnf: { jwk },
    } = await verifyIssuerSignedJwt(issuerJwt);
    // 4)
    let holderPublicKeyPem: string;
    try {
      holderPublicKeyPem = jwkToPem(jwk as JWK);
    } catch {
      throw new ForbiddenError(
        "The public key in the issuer signed JWT is malformed",
      );
    }
    const decodedKbJwt = await verifyKbJwt(kbJwt, holderPublicKeyPem)(clientId);
    const disclosuresBase64Url = disclosures.map(base64ToBase64Url);
    // 5)
    verifyDisclosuresSdMatch(disclosuresBase64Url, _sd);
    // 6)
    verifySdHash({
      disclosures: disclosuresBase64Url,
      issuerJwt,
      sdHash: decodedKbJwt.sd_hash,
    });
  };
}

// this is called for each sdjwt in the vpToken
function verifySdJwt(
  sdJwtId: string,
  sdJwt: string,
  format: "dc+sd-jwt" | "vc+sd-jwt",
): (clientId: string) => Promise<{
  dcqlPresentation: Record<
    string,
    {
      claims: Record<string, unknown>;
      credential_format: "dc+sd-jwt" | "vc+sd-jwt";
      vct: string;
    }
  >;
  nonce: string | undefined;
}> {
  return async function (clientId) {
    const splittedSdJwt = sdJwt.split("~");
    const issuerJwt = splittedSdJwt[0];
    const disclosures = splittedSdJwt.slice(1, -1);
    const kbJwt = splittedSdJwt[splittedSdJwt.length - 1];
    const decodedJwt = jwt.decode(issuerJwt);
    if (!decodedJwt || typeof decodedJwt === "string") {
      throw new BadRequestError("Credential payload is not valid");
    }

    // 3)
    // check if the credential is the wallet attestation
    let nonce: string | undefined;
    if (
      decodedJwt.vct ===
      "https://pre.ta.wallet.ipzs.it/vct/v1.0.0/WalletAttestation"
    ) {
      await verifyWalletAttestation({ disclosures, issuerJwt, kbJwt })(
        clientId,
      );
    } else {
      const decodedKbJwt = jwt.decode(kbJwt);
      if (!decodedKbJwt || typeof decodedKbJwt === "string") {
        throw new BadRequestError("Credential KB-JWT payload is not valid");
      }
      await verifyIssuerCredentialJwt({
        disclosures,
        issuerJwt,
        kbJwt,
      })(clientId);

      nonce = decodedKbJwt.nonce;
    }

    const decodedDisclosures = disclosures.map((disclosure) =>
      JSON.parse(Buffer.from(disclosure, "base64").toString()),
    );

    return {
      dcqlPresentation: {
        [sdJwtId]: fromVpTokenToLibraryObjects(
          decodedDisclosures,
          decodedJwt.vct,
          format,
        ),
      },
      nonce,
    };
  };
}

// 7)
function convertDisclosuresToClaimsObject(
  disclosures: Disclosure[],
): ClaimsObject {
  return disclosures.reduce((result: ClaimsObject, disclosure) => {
    const [, claimName, claimValue] = disclosure;

    if (!result[claimName]) {
      result[claimName] = {};
    }

    result[claimName][claimValue + ""] = {};

    return result;
  }, {});
}

const fromVpTokenToLibraryObjects: (
  decodedDisclosures: Disclosure[],
  vct: string,
  format: "dc+sd-jwt" | "vc+sd-jwt",
) => {
  claims: Record<string, unknown>;
  credential_format: "dc+sd-jwt" | "vc+sd-jwt";
  vct: string;
} = (decodedDisclosures, vct, format) => ({
  claims: convertDisclosuresToClaimsObject(decodedDisclosures), // TODO: change name
  credential_format: format,
  vct,
});

const checkPresentation: ({
  dcqlPresentation,
  dcqlQuery,
}: {
  dcqlPresentation: DcqlPresentation;
  dcqlQuery: DcqlQuery.Output;
}) => void = ({ dcqlPresentation, dcqlQuery }) => {
  try {
    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(
      dcqlPresentation,
      { dcqlQuery },
    );

    if (!presentationQueryResult.canBeSatisfied) {
      throw new Error();
    }
  } catch {
    throw new BadRequestError(
      "The credential presentation does not have required parameters",
    );
  }
};

function allEqual(array: unknown[]) {
  return array.every((val) => val === array[0]);
}

function checkNonce(
  localNonces: string[],
): (nonceRepository: NonceRepository) => Promise<void> {
  return async function (nonceRepository) {
    if (allEqual(localNonces)) {
      try {
        await getNonce(localNonces[0])(nonceRepository);
      } catch (error) {
        throw error instanceof NotFoundError
          ? new ForbiddenError(
              "The nonce does not match with the one provided in the request object",
            )
          : error;
      }
    }
  };
}

function getDcqlQuery(requestObject: RequestObject): Promise<DcqlQuery.Output> {
  try {
    if (requestObject.status !== "checking") {
      throw new Error();
    }
    const decodedRequestObject = jwt.decode(requestObject.jwt);
    if (!decodedRequestObject || typeof decodedRequestObject === "string") {
      throw new Error();
    }
    return decodedRequestObject.dcql_query; // TODO: il parse?
  } catch {
    throw new Error("Can not retrieve dcql query from request object");
  }
}

// this is the `handler` function that is called when the wallet sends a `response` to the RP
export function baz1(
  bodyResponse: string,
): (dep: {
  config: Config;
  nonceRepository: NonceRepository;
  requestObjectRepository: RequestObjectRepository;
}) => Promise<{ redirect_uri?: string }> {
  return async function ({ config, nonceRepository, requestObjectRepository }) {
    const { state, vpToken } = await verifyAuthorizationResponse(bodyResponse)(
      config.authResponsePrivateKey,
    );

    // 3) / 4) / 5) / 6)
    try {
      const requestObject = await getRequestObject(state)(
        requestObjectRepository,
      );

      const decodedRequestObject = jwt.decode(requestObject.jwt);

      const Credentials = z.object({
        dcql_query: z.object({
          credentials: z.array(
            z.object({
              format: z.enum(["dc+sd-jwt", "vc+sd-jwt"]),
              id: z.string(),
            }),
          ),
        }),
      });

      const parsedRequestObject = Credentials.parse(decodedRequestObject);

      const credentialArray = parsedRequestObject.dcql_query.credentials;

      const formatById: Record<string, "dc+sd-jwt" | "vc+sd-jwt"> = {};
      for (const item of credentialArray) {
        formatById[item.id] = item.format;
      }

      // Also build format lookup by index (for wallets that use numeric keys)
      const formatByIndex: Record<string, "dc+sd-jwt" | "vc+sd-jwt"> = {};
      credentialArray.forEach((item, index) => {
        formatByIndex[index.toString()] = item.format;
      });

      const resultPromises = Object.entries(vpToken).map(
        async ([sdJwtId, sdJwt]) => {
          // Try to get format by ID first, then fall back to index-based lookup
          const format = formatById[sdJwtId] ?? formatByIndex[sdJwtId];
          if (!format) {
            throw new BadRequestError(
              `Unknown credential ID "${sdJwtId}" in VP Token`,
            );
          }
          return verifySdJwt(sdJwtId, sdJwt, format)(config.clientId);
        },
      );

      const result = await Promise.all(resultPromises);

      const localNonces = result
        .map(({ nonce }) => nonce)
        .filter((n): n is string => typeof n === "string");

      // if an error occurs before this point, the `nonce` is not deleted
      await checkNonce(localNonces)(nonceRepository);

      // 7)
      const dcqlPresentation: DcqlPresentation = {};
      result.forEach((entry) => {
        const presentation = entry.dcqlPresentation;
        for (const key in presentation) {
          if (Object.prototype.hasOwnProperty.call(presentation, key)) {
            // this if is for the linter
            dcqlPresentation[key] = presentation[key];
          }
        }
      });

      const dcqlQuery = await getDcqlQuery(requestObject);
      checkPresentation({
        dcqlPresentation,
        dcqlQuery,
      });

      const redirectUri = `${config.basePath}/success.html`;
      const responseCode = crypto.randomBytes(32).toString("hex");
      const fullRedirectUri = `${redirectUri}?response_code=${responseCode}`;
      await markRequestObjectAsVerified(
        state,
        fullRedirectUri,
        dcqlPresentation,
      )(requestObjectRepository);
      return {
        redirect_uri: fullRedirectUri,
      };
    } catch (error) {
      await markRequestObjectAsDenied(state)(requestObjectRepository);
      throw error;
    }
  };
}
