import { request } from 'node:https';
import { rootCertificates } from 'node:tls';

import { INTERNAL_SERVICE_REQUEST_HEADER } from '@itw-conformance-tool/utils';

import type { TrustChain } from '@pagopa/io-wallet-oauth2';

/**
 * Assembly of the federation Trust Chain the Relying Party can inline in a
 * Request Object header instead of leaving the wallet to resolve it.
 *
 * A Trust Chain is the ordered sequence of entity statements that binds a leaf
 * to a Trust Anchor, and OpenID Federation fixes that order: the leaf Entity
 * Configuration first, then each Subordinate Statement about the entity below
 * it, and the Trust Anchor's own Entity Configuration last. With a single
 * Trust Anchor and no intermediates, that is exactly three statements — and
 * they are the same three artifacts a wallet would otherwise fetch itself, so
 * they are taken from the very endpoints that serve them rather than rebuilt.
 *
 * The two Trust Anchor statements cannot be produced locally: both are signed
 * with the Trust Anchor's federation key, which lives in another process. They
 * are therefore fetched over HTTP, marked as internal
 * (`INTERNAL_SERVICE_REQUEST_HEADER`) so the Trust Anchor does not record them
 * as the wallet having resolved anything.
 */

const TRUST_ANCHOR_FETCH_TIMEOUT_MS = 10_000;
const SUBORDINATE_STATEMENT_PATH = '/fetch';
const ENTITY_CONFIGURATION_PATH = '/.well-known/openid-federation';

/** Names this Relying Party as the caller in the Trust Anchor's request log. */
const INTERNAL_REQUEST_PURPOSE = 'relying-party-trust-chain-assembly';

/**
 * Fetches one entity statement from the Trust Anchor.
 *
 * TLS is verified. The local Trust Anchor answers on a certificate signed by
 * the self-signed root CA `itwct init` generates, which no public trust store
 * knows about, so that CA is *added to* the default roots rather than replacing
 * them: a Trust Anchor configured at a public URL keeps being verified against
 * the public authorities.
 *
 * @param trustAnchorTlsCa - PEM-encoded certificate authority to trust on top of
 *   the public roots, or `undefined` to verify against the public roots alone.
 */
async function fetchEntityStatement(url: URL, trustAnchorTlsCa?: string): Promise<string> {
  if (url.protocol !== 'https:') {
    throw new Error(`The Trust Anchor must be reachable over HTTPS to assemble a Trust Chain, got ${url.protocol}`);
  }

  return new Promise((resolve, reject) => {
    const req = request(
      {
        ...(trustAnchorTlsCa === undefined ? {} : { ca: [...rootCertificates, trustAnchorTlsCa] }),
        headers: { [INTERNAL_SERVICE_REQUEST_HEADER]: INTERNAL_REQUEST_PURPOSE },
        hostname: url.hostname,
        method: 'GET',
        path: `${url.pathname}${url.search}`,
        port: url.port,
        protocol: url.protocol,
        rejectUnauthorized: true,
        timeout: TRUST_ANCHOR_FETCH_TIMEOUT_MS
      },
      (response) => {
        const chunks: Buffer[] = [];

        response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        response.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8').trim();

          if (response.statusCode !== 200) {
            reject(new Error(`${url.toString()} answered ${response.statusCode ?? 'no status'}: ${body}`));
            return;
          }

          if (body.length === 0) {
            reject(new Error(`${url.toString()} answered with an empty entity statement`));
            return;
          }

          resolve(body);
        });
      }
    );

    req.on('timeout', () =>
      req.destroy(new Error(`${url.toString()} did not answer within ${TRUST_ANCHOR_FETCH_TIMEOUT_MS}ms`))
    );
    req.on('error', reject);
    req.end();
  });
}

export interface BuildRelyingPartyTrustChainOptions {
  /** The Relying Party Entity Configuration, already signed. */
  entityConfigurationJwt: string;
  /** The Relying Party entity identifier, i.e. the `sub` the Trust Anchor attests. */
  relyingPartyEntityId: string;
  /**
   * PEM-encoded certificate authority that signed the Trust Anchor TLS
   * certificate, for a Trust Anchor no public authority vouches for — locally,
   * the self-signed root CA every service in the tool runs on. Omitted, the
   * Trust Anchor is verified against the public roots alone.
   */
  trustAnchorTlsCa?: string;
  trustAnchorUrl: string;
}

/**
 * Builds the Trust Chain that binds this Relying Party to the Trust Anchor.
 *
 * @returns `[Relying Party Entity Configuration, Subordinate Statement, Trust Anchor Entity Configuration]`.
 * @throws When the Trust Anchor does not serve either of its two statements, so
 *   a Request Object is never signed over a Trust Chain that cannot be verified.
 */
export async function buildRelyingPartyTrustChain(options: BuildRelyingPartyTrustChainOptions): Promise<TrustChain> {
  const { entityConfigurationJwt, relyingPartyEntityId, trustAnchorTlsCa, trustAnchorUrl } = options;

  const subordinateStatementUrl = new URL(SUBORDINATE_STATEMENT_PATH, trustAnchorUrl);
  subordinateStatementUrl.searchParams.set('sub', relyingPartyEntityId);

  const [subordinateStatement, trustAnchorEntityConfiguration] = await Promise.all([
    fetchEntityStatement(subordinateStatementUrl, trustAnchorTlsCa),
    fetchEntityStatement(new URL(ENTITY_CONFIGURATION_PATH, trustAnchorUrl), trustAnchorTlsCa)
  ]);

  return [entityConfigurationJwt, subordinateStatement, trustAnchorEntityConfiguration];
}
