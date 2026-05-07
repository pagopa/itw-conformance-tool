import {
  CoseKey,
  DeviceKey,
  Holder,
  Issuer,
  SignatureAlgorithm,
} from "@owf/mdoc";
import { X509CertificateGenerator } from "@peculiar/x509";
import { describe, expect, it } from "vitest";

import { mdocContext } from "../context";

const DOC_TYPE = "org.iso.18013.5.1.mDL";
const NAMESPACE = "org.iso.18013.5.1";
const SIGNING_ALGORITHM = {
  hash: "SHA-256",
  name: "ECDSA",
} as const;

const generateEcKeyPair = async (): Promise<CryptoKeyPair> =>
  await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"],
  );

const exportCoseKey = async (key: CryptoKey): Promise<CoseKey> =>
  CoseKey.fromJwk(
    (await crypto.subtle.exportKey("jwk", key)) as Record<string, unknown>,
  );

const createCertificateChain = async (now: Date) => {
  const rootKeys = await generateEcKeyPair();
  const leafKeys = await generateEcKeyPair();

  const rootCertificate = await X509CertificateGenerator.createSelfSigned({
    keys: rootKeys,
    name: "C=IT, CN=mdoc-root",
    notAfter: new Date("2030-01-01T00:00:00.000Z"),
    notBefore: new Date("2024-01-01T00:00:00.000Z"),
    signingAlgorithm: SIGNING_ALGORITHM,
  });

  const leafCertificate = await X509CertificateGenerator.create({
    issuer: rootCertificate.subject,
    notAfter: new Date("2028-01-01T00:00:00.000Z"),
    notBefore: new Date("2024-01-01T00:00:00.000Z"),
    publicKey: leafKeys.publicKey,
    signingAlgorithm: SIGNING_ALGORITHM,
    signingKey: rootKeys.privateKey,
    subject: "C=IT, CN=mdoc-leaf",
  });

  return {
    holderPublicJwk: (await crypto.subtle.exportKey(
      "jwk",
      (await generateEcKeyPair()).publicKey,
    )) as Record<string, unknown>,
    issuerKey: await exportCoseKey(leafKeys.privateKey),
    now,
    trustedCertificate: new Uint8Array(rootCertificate.rawData),
    x5chain: [
      new Uint8Array(leafCertificate.rawData),
      new Uint8Array(rootCertificate.rawData),
    ] as [Uint8Array, Uint8Array],
  };
};

const issueCredential = async (
  now: Date,
): Promise<{
  encoded: string;
  trustedCertificate: Uint8Array;
}> => {
  const { holderPublicJwk, issuerKey, trustedCertificate, x5chain } =
    await createCertificateChain(now);
  const issuer = new Issuer(DOC_TYPE, mdocContext);

  issuer.addIssuerNamespace(NAMESPACE, {
    family_name: "Rossi",
    given_name: "Mario",
  });

  const issuerSigned = await issuer.sign({
    algorithm: SignatureAlgorithm.ES256,
    certificates: x5chain,
    deviceKeyInfo: {
      deviceKey: DeviceKey.fromJwk(holderPublicJwk),
    },
    digestAlgorithm: "SHA-256",
    signingKey: issuerKey,
    validityInfo: {
      signed: now,
      validFrom: now,
      validUntil: new Date("2027-01-01T00:00:00.000Z"),
    },
  });

  return {
    encoded: issuerSigned.encodedForOid4Vci,
    trustedCertificate,
  };
};

describe("mdocContext integration", () => {
  it("verifies an issued credential through the real OWF verifier", async () => {
    const now = new Date("2026-01-09T11:50:00.000Z");
    const { encoded, trustedCertificate } = await issueCredential(now);

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: encoded,
          now,
          trustedCertificates: [trustedCertificate],
        },
        mdocContext,
      ),
    ).resolves.toBeUndefined();
  });
});
