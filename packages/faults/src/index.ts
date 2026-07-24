export {
  credentialResponseFaultParameters,
  digitalCredentialClaimsFaultVariants,
  issuerFaultProfileSchema,
  parseIssuerFaultProfile,
  type CredentialResponseFaultParameter,
  type DigitalCredentialClaimsFaultVariant,
  type IssuerFaultProfile,
  type IssuerFaultProfileType
} from './issuer-fault-profile.js';
export {
  getIssuerFaultCatalogEntry,
  isSupportedItWalletSpecVersion,
  issuerFaultCatalog,
  supportedItWalletSpecVersions,
  validateIssuerFaultActivation,
  type IssuerFaultApplicationPoint,
  type IssuerFaultCatalogEntry,
  type IssuerFaultMutationTiming,
  type IssuerFaultValidationFailure,
  type IssuerFaultValidationFailureCode,
  type IssuerFaultValidationResult,
  type IssuerFaultValidationSuccess,
  type SupportedItWalletSpecVersion
} from './issuer-fault-catalog.js';
