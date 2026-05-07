import { CoseKey, DeviceKey, Issuer, SignatureAlgorithm } from "@owf/mdoc";

import type { JwksRepository } from "../signer";
import type { JwkPublicKey } from "../z-jwk";
import type { MdocDocumentDefinition } from "./documents";

import { mdocContext } from "./context";
import { pemToDer, stripKid } from "./utils";

export const createMdocCredential = async (
  document: MdocDocumentDefinition,
  jwksRepository: JwksRepository,
  holderPublicKey: JwkPublicKey,
): Promise<string> => {
  const issuer = new Issuer(document.docType, mdocContext);
  Object.entries(document.namespaces).forEach(([namespace, claims]) => {
    issuer.addIssuerNamespace(namespace, claims);
  });

  const issuerSigned = await issuer.sign({
    algorithm: SignatureAlgorithm.ES256,
    certificates: [pemToDer(jwksRepository.iacaX509())],
    deviceKeyInfo: {
      deviceKey: DeviceKey.fromJwk(stripKid(holderPublicKey)),
    },
    digestAlgorithm: "SHA-256",
    signingKey: CoseKey.fromJwk(stripKid(jwksRepository.getSign().private)),
    validityInfo: document.validityInfo,
  });

  return issuerSigned.encodedForOid4Vci;
};
