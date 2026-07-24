import { createHash } from 'node:crypto';

/**
 * Hashes a serialized response artifact for safe inclusion in
 * `issuer.fault.applied` evidence. Shared by every fault application point
 * (Entity Configuration, Credential Response, ...) so evidence always
 * reports the same `sha256:<base64url>` format instead of each route
 * inventing a subtly different one.
 */
export function sha256HashArtifact(value: string): string {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('base64url')}`;
}
