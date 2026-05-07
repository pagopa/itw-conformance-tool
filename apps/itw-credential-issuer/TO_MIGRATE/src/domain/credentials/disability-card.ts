import type { JwksRepository } from "@/domain/signer";
import type { JwkPublicKey } from "@/domain/z-jwk";
import type { DisclosureFrame } from "@sd-jwt/types";

import { FakeUser } from "@/domain/faker";
import { createSRIHash, createSignerVerifier } from "@/domain/sd-jwt";
import { createBase64Portrait } from "@/domain/utils/portrait";
import { STATUS_LIST_URI } from "@/domain/utils/status-list";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { ES256, digest, generateSalt } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";

export const DISABILITY_CARD_SCOPE = "EuropeanDisabilityCard";
export const DISABILITY_CARD_ID = "dc_sd_jwt_EuropeanDisabilityCard";
export const DISABILITY_CARD_VCT = "urn:eu.europa.ec.eudi:edc:1";

/**
 * European Disability Card Credential
 *
 * credential_configurations_supported: `dc_sd_jwt_EuropeanDisabilityCard`
 * scope: `EuropeanDisabilityCard`
 * format: `sd-jwt`
 */
export async function createDisabilityCardCredential(
  iss: string,
  jwksRepository: JwksRepository,
  holderPublicKey: JwkPublicKey,
  config: IoWalletSdkConfig,
  fakeUser: FakeUser,
): Promise<string> {
  const jwks = jwksRepository.getSign();

  const [signer, verifier] = await createSignerVerifier({
    privateKey: jwks.private,
    publicKey: holderPublicKey,
  });

  // Create SDJwt instance for use
  const sdjwt = new SDJwtVcInstance({
    hashAlg: "sha-256",
    hasher: digest,
    saltGenerator: generateSalt,
    signAlg: ES256.alg,
    signer,
    verifier,
  });

  const now = new Date();
  const expiration = new Date(now.getTime() + 24 * 60 * 60 * 1000 * 355); // plus 1 year

  const claims = {
    birth_date: fakeUser.birthDate,
    constant_attendance_allowance: true,
    document_number: fakeUser.documentNumber,
    expiry_date: expiration.toISOString().slice(0, 10), // "YYYY-MM-DD"
    family_name: fakeUser.familyName,
    given_name: fakeUser.givenName,
    issuing_authority: "PagoPA S.p.A.",
    issuing_country: "IT",
    link_qr_code: `https://example.com/verify?vc=${fakeUser.documentNumber}`,
    personal_administrative_number: fakeUser.fiscalCode,
    portrait: createBase64Portrait(),
  };

  // Issuer Define the disclosure frame to specify which claims can be disclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: [
      "birth_date",
      "constant_attendance_allowance",
      "document_number",
      "expiry_date",
      "family_name",
      "given_name",
      "link_qr_code",
      "personal_administrative_number",
      "portrait",
    ],
  };

  const vctIntegrity = createSRIHash(DISABILITY_CARD_VCT);

  // Issue a signed JWT credential with the specified claims and disclosures
  // Return a Encoded SD JWT. Issuer send the credential to the holder
  const credential = await sdjwt.issue(
    {
      cnf: { jwk: holderPublicKey },
      exp: Math.floor(expiration.getTime() / 1000),
      iat: Math.floor(now.getTime() / 1000),
      iss,
      status: {
        ...(config.isVersion(ItWalletSpecsVersion.V1_0) && {
          status_assertion: { credential_hash_alg: "sha-256" },
        }),

        status_list: {
          idx: 1,
          uri: STATUS_LIST_URI(iss),
        },
      },
      sub: holderPublicKey.kid,
      vct: DISABILITY_CARD_VCT,
      "vct#Integrity": vctIntegrity,
      // verification
      ...claims,
    },
    disclosureFrame,
    {
      header: {
        kid: jwks.private.kid,
        typ: "dc+sd-jwt",
        x5c: [jwksRepository.iacaX509()],
      },
    },
  );

  return credential;
}
