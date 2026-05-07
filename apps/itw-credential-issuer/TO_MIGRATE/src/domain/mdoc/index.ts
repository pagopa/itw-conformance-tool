import { FakeUser } from "@/domain/faker";
import { IoWalletSdkConfig } from "@pagopa/io-wallet-utils";

import type { MdocSupportedCredentialsId } from "../z-credential";
import type { JwkPublicKey } from "../z-jwk";
import type { MdocDocumentDefinition } from "./documents";

import {
  getCompanyBadgeDocument,
  getMdlDocument,
  getPidMdocDocument,
} from "./documents";

export {
  BADGE_DOCTYPE,
  BADGE_NAMESPACE,
  MDL_DOCTYPE,
  MDL_NAMESPACE,
  PID_MDOC_DOCTYPE,
  PID_MDOC_IT_NAMESPACE,
  PID_MDOC_NAMESPACE,
} from "./documents";
export { createMdocCredential } from "./issue";

export const getMdocCredentialDefinition = (
  credentialIdentifier: MdocSupportedCredentialsId,
  config: IoWalletSdkConfig,
  holderPublicKey: JwkPublicKey,
  fakeUser: FakeUser,
): MdocDocumentDefinition => {
  if (
    credentialIdentifier === "org.iso.18013.5.1.mDL" ||
    credentialIdentifier === "mso_mdoc_mDL"
  ) {
    return getMdlDocument(fakeUser);
  }

  if (credentialIdentifier === "mso_mdoc_CompanyBadge") {
    return getCompanyBadgeDocument(holderPublicKey.kid, fakeUser);
  }

  if (credentialIdentifier === "mso_mdoc_PersonIdentificationData") {
    return getPidMdocDocument(config, fakeUser);
  }

  const unsupportedCredentialIdentifier: never = credentialIdentifier;
  throw new Error(
    `Unsupported mdoc credential identifier: ${unsupportedCredentialIdentifier}`,
  );
};
