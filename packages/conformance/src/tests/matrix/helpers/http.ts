const REQUEST_TIMEOUT_MS = 5_000;

import { decodeJwt } from 'jose';

export function normalizeUrl(url: string): string {
  let normalized = url;
  while (normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

export async function wpFetch(url: string, init?: RequestInit): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
}

export async function readJsonBody<T>(response: Response): Promise<T> {
  return response.json() as Promise<T>;
}

export function hasCompactJwtShape(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

export function resolveTrustAnchorUrl(federationJwt: string): string {
  const envUrl = process.env.ITW_CT_RP_TRUST_ANCHOR_URL?.trim();
  if (envUrl) {
    return normalizeUrl(envUrl);
  }

  const payload = decodeJwt(federationJwt) as { authority_hints?: string[] };
  const authorityHint = payload.authority_hints?.[0];
  if (typeof authorityHint === 'string' && authorityHint.startsWith('https://')) {
    return normalizeUrl(authorityHint);
  }

  throw new Error('Unable to resolve Trust Anchor URL: set ITW_CT_RP_TRUST_ANCHOR_URL or authority_hints');
}
