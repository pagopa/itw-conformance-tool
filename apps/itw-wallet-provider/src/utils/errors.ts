import z from 'zod';

import type { FastifyReply } from 'fastify';

/**
 * Wallet Provider error bodies carry two overlapping vocabularies on purpose.
 *
 * The IT-Wallet test matrix mandates the OAuth-style `error` / `error_description`
 * pair, while `io-react-native-wallet` parses every failed response as RFC 9457
 * Problem Details (`src/client/index.ts`) and collapses anything it cannot parse
 * into a generic "Invalid response from Wallet Provider". Emitting both keeps the
 * spec assertions intact and lets the real client surface the actual reason.
 */
export const problemJsonSchemaShape = {
  type: z.string().describe('Absolute URI identifying the problem type.'),
  title: z.string().describe('Short summary of the problem type.'),
  status: z.number().int().describe('HTTP status code generated for this occurrence.'),
  detail: z.string().describe('Human readable explanation specific to this occurrence.')
};

export const walletProviderErrorSchema = <T extends readonly [string, ...string[]]>(errorCodes: T) =>
  z.object({
    error: z.enum(errorCodes).describe('Machine-readable error code.'),
    error_description: z.string().min(1).describe('Human-readable error description.'),
    ...problemJsonSchemaShape
  });

export type WalletProviderErrorBody = {
  detail: string;
  error: string;
  error_description: string;
  status: number;
  title: string;
  type: string;
};

export function toWalletProviderErrorBody(
  statusCode: number,
  error: string,
  description: string
): WalletProviderErrorBody {
  return {
    detail: description,
    error,
    error_description: description,
    status: statusCode,
    title: error,
    type: 'about:blank'
  };
}

export function sendWalletProviderError(
  reply: FastifyReply,
  statusCode: number,
  error: string,
  description: string
): FastifyReply {
  return reply
    .code(statusCode)
    .type('application/json')
    .header('cache-control', 'no-store')
    .send(toWalletProviderErrorBody(statusCode, error, description));
}
