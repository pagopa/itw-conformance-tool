import type { ConformancePhase, ConformanceStep } from '../models/types.js';

export interface RequirementDefinition {
  requirementId: string;
  description: string;
}

type RequirementKey = `${ConformanceStep}:${ConformancePhase}`;

const REQUIREMENT_MAP: Partial<Record<RequirementKey, RequirementDefinition[]>> = {
  'PAR:ISSUANCE': [
    {
      requirementId: 'IT-WALLET-1.4-§4.2.1',
      description: 'PAR request contains a valid Wallet Attestation JWT'
    }
  ],
  'AUTHORIZE:ISSUANCE': [
    {
      requirementId: 'IT-WALLET-1.4-§4.2.2',
      description: 'Authorization request references a valid PAR request_uri'
    }
  ],
  'PRESENTATION_RESPONSE:ISSUANCE': [
    {
      requirementId: 'IT-WALLET-1.4-§4.2.3',
      description: 'Presentation response contains a valid VP Token'
    }
  ],
  'AUTHORIZATION_CODE:ISSUANCE': [
    {
      requirementId: 'IT-WALLET-1.4-§4.2.4',
      description: 'Authorization code JWT is correctly formed and signed'
    }
  ],
  'TOKEN:ISSUANCE': [
    {
      requirementId: 'IT-WALLET-1.4-§4.3.2',
      description: 'Token request includes a valid DPoP proof'
    }
  ],
  'NONCE:ISSUANCE': [
    {
      requirementId: 'IT-WALLET-1.4-§4.3.3',
      description: 'Nonce endpoint returns a valid c_nonce'
    }
  ],
  'CREDENTIAL:ISSUANCE': [
    {
      requirementId: 'IT-WALLET-1.4-§4.3.4',
      description: 'Credential request includes a valid key proof'
    }
  ],
  'AUTHORIZE:PRESENTATION': [
    {
      requirementId: 'IT-WALLET-1.4-§5.2.1',
      description: 'Authorization request object is a valid signed JAR'
    }
  ],
  'PRESENTATION_RESPONSE:PRESENTATION': [
    {
      requirementId: 'IT-WALLET-1.4-§5.2.2',
      description: 'Presentation response contains a valid encrypted VP Token with KB-JWT'
    }
  ]
};

/**
 * Returns the requirement definitions associated with a given conformance step and phase.
 *
 * Returns an empty array for step/phase combinations that have no defined requirements
 * (e.g. PAR:PRESENTATION, which does not exist in the RP flow).
 */
export function getRequirements(step: ConformanceStep, phase: ConformancePhase): RequirementDefinition[] {
  const key: RequirementKey = `${step}:${phase}`;
  return REQUIREMENT_MAP[key] ?? [];
}
