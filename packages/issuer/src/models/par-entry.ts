import type { ParRequest } from '../z-par.js';

export type { ParRequest };

export interface ParEntryRecord {
  readonly requestUri: string;
  readonly clientId: string;
  readonly parRequest: ParRequest;
  readonly expiresAt: number;
  readonly code?: string;
  readonly codeExpiresAt?: number;
}

export const PAR_TTL_MS = 60_000; // 60 seconds
export const CODE_TTL_SECONDS = 300; // 5 minutes
