import type { RedactedHeaders } from './event-types.js';
import type { IncomingHttpHeaders } from 'node:http';

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'cookie',
  'dpop',
  'proxy-authorization',
  'set-cookie',
  'x-api-key'
]);

const SENSITIVE_FIELD_NAMES = new Set([
  'access_token',
  'assertion',
  'client_assertion',
  'credential',
  'id_token',
  'password',
  'refresh_token',
  'request',
  'request_object',
  'token',
  'vp_token'
]);

export const REDACTED_VALUE = '[REDACTED]';

export function redactHeaders(headers: IncomingHttpHeaders | Record<string, unknown>): RedactedHeaders {
  const redacted: RedactedHeaders = {};

  for (const [name, value] of Object.entries(headers)) {
    const normalizedName = name.toLowerCase();
    if (SENSITIVE_HEADER_NAMES.has(normalizedName)) {
      redacted[normalizedName] = REDACTED_VALUE;
      continue;
    }

    if (Array.isArray(value)) {
      redacted[normalizedName] = value.map(String);
    } else if (value === undefined) {
      redacted[normalizedName] = undefined;
    } else {
      redacted[normalizedName] = String(value);
    }
  }

  return redacted;
}

export function redactJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactJson);

  if (!value || typeof value !== 'object') return value;

  const redacted: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    redacted[key] = SENSITIVE_FIELD_NAMES.has(key.toLowerCase()) ? REDACTED_VALUE : redactJson(child);
  }
  return redacted;
}

export function toReportablePayload(payload: unknown, maxBytes: number): unknown {
  if (payload === undefined || payload === null) return payload;

  const value = Buffer.isBuffer(payload) ? payload.toString('utf-8') : payload;
  const redacted = typeof value === 'object' ? redactJson(value) : value;
  const serialized = typeof redacted === 'string' ? redacted : JSON.stringify(redacted);

  if (Buffer.byteLength(serialized, 'utf-8') <= maxBytes) return redacted;

  return {
    truncated: true,
    originalBytes: Buffer.byteLength(serialized, 'utf-8'),
    preview: serialized.slice(0, maxBytes)
  };
}
