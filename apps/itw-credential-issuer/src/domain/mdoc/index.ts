import { getCompanyBadgeDocument, getMdlDocument, getPidMdocDocument } from './documents/index.js';

import type { FakeUser } from '../faker.js';
import type { MdocSupportedCredentialsId } from '../z-credential.js';
import type { JwkPublicKey } from '../z-jwk.js';
import type { MdocDocumentDefinition } from './documents/index.js';
import type { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

export {
  BADGE_DOCTYPE,
  BADGE_NAMESPACE,
  MDL_DOCTYPE,
  MDL_NAMESPACE,
  PID_MDOC_DOCTYPE,
  PID_MDOC_IT_NAMESPACE,
  PID_MDOC_NAMESPACE
} from './documents/index.js';
export { createMdocCredential } from './issue.js';
export { createOid4VpSessionTranscript, pemToDer, stripKid } from './utils.js';

export const getMdocCredentialDefinition = (
  credentialIdentifier: MdocSupportedCredentialsId,
  config: IoWalletSdkConfig,
  holderPublicKey: JwkPublicKey,
  fakeUser: FakeUser
): MdocDocumentDefinition => {
  if (credentialIdentifier === 'org.iso.18013.5.1.mDL' || credentialIdentifier === 'mso_mdoc_mDL') {
    return getMdlDocument(fakeUser);
  }

  if (credentialIdentifier === 'mso_mdoc_CompanyBadge') {
    if (!holderPublicKey.kid) {
      throw new Error('Holder public key must have a kid for CompanyBadge credential');
    }
    return getCompanyBadgeDocument(holderPublicKey.kid, fakeUser);
  }

  if (credentialIdentifier === 'mso_mdoc_PersonIdentificationData') {
    return getPidMdocDocument(config, fakeUser);
  }

  const unsupportedCredentialIdentifier: never = credentialIdentifier;
  throw new Error(`Unsupported mdoc credential identifier: ${unsupportedCredentialIdentifier}`);
};
