import type { ArtifactRef } from '../artifacts/artifact-store.js';

export interface ArtifactValidationResult {
  expectationId: string;
  eventId: string;
  artifactRef: ArtifactRef;
  status: 'invalid' | 'not-applicable' | 'valid';
  reason?: string;
  evidence?: { message: string }[];
}
