import { z } from "zod";

/**
 * Union type that represents the supported credentials.
 * This simplifies the type definition of the `credential` store.
 */
export type SupportedCredentialsType =
  | "EuropeanDisabilityCard"
  | "EuropeanHealthInsuranceCard"
  | "PersonIdentificationData"
  | "eu.europa.ec.eudi.hiid.1"
  | "org.iso.18013.5.1.mDL"
  | "urn:eu.europa.ec.eudi:pid:1";

export const SupportedCredentialsId = z.union([
  z.literal("dc_sd_jwt_EuropeanDisabilityCard"),
  z.literal("dc_sd_jwt_PersonIdentificationData"),
  z.literal("mso_mdoc_CompanyBadge"),
  z.literal("mso_mdoc_PersonIdentificationData"),
  z.literal("mso_mdoc_mDL"),
  z.literal("org.iso.18013.5.1.mDL"),
]);

/**
 * Union type that represents the supported credentials.
 * This simplifies the type definition of the `credential` store.
 */
export type SupportedCredentialsId = z.infer<typeof SupportedCredentialsId>;

export type MdocSupportedCredentialsId = Extract<
  SupportedCredentialsId,
  | "mso_mdoc_CompanyBadge"
  | "mso_mdoc_PersonIdentificationData"
  | "mso_mdoc_mDL"
  | "org.iso.18013.5.1.mDL"
>;
