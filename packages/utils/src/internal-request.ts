import type { IncomingHttpHeaders } from 'node:http';

/**
 * Header a conformance-tool service sets on the HTTP calls it makes to another
 * conformance-tool service *on its own behalf* — never on behalf of the Wallet
 * Instance under test.
 *
 * The federation endpoints double as observation points: a request to the Trust
 * Anchor `/fetch` or `/.well-known/openid-federation` is recorded as evidence
 * that the wallet resolved the Trust Chain. A service that calls those same
 * endpoints to assemble an artifact would forge that evidence, so it marks its
 * requests with this header and the handlers skip the semantic emission. The
 * generic `http.*` instrumentation still records the exchange: it happened, and
 * no scenario reads those events as protocol evidence.
 */
export const INTERNAL_SERVICE_REQUEST_HEADER = 'x-itwct-internal-request';

/**
 * Whether a request came from another conformance-tool service rather than from
 * the Wallet Instance under test, and therefore must not produce protocol
 * evidence.
 *
 * @param headers - The incoming request headers.
 */
export function isInternalServiceRequest(headers: IncomingHttpHeaders): boolean {
  return headers[INTERNAL_SERVICE_REQUEST_HEADER] !== undefined;
}
