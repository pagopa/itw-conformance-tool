import { httpsRequest } from '../utils/request.js';

export function createDefaultPresentationDcqlQuery(): Record<string, unknown> {
  return {
    credentials: [
      {
        id: 'pid',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['urn:eudi:pid:it:1'] },
        claims: [{ path: ['given_name'] }, { path: ['family_name'] }, { path: ['birthdate'] }]
      }
    ]
  };
}

export type PresentationFlowType = 'cross-device' | 'same-device';

/**
 * Retrieval method the engagement advertises for the `request_uri`. Left
 * undefined the parameter is omitted, so a wallet falls back to `get`
 * (WP_082); `'post'` exercises the POST retrieval with `wallet_metadata` and
 * `wallet_nonce` (WP_083).
 */
export type PresentationRequestUriMethod = 'get' | 'post';

/**
 * Client Identifier Prefix the engagement announces, which decides how the
 * wallet establishes trust in the Relying Party: through the `x5c` certificate
 * chain and the inline `client_metadata` (`x509_hash`), or through the
 * federation Trust Chain and the Entity Configuration (`openid_federation`).
 */
export type PresentationClientIdPrefix = 'openid_federation' | 'x509_hash';

export interface CreatePresentationRequestUriOptions {
  /** Omitted, the Relying Party applies its IT Wallet 1.3 default (`x509_hash`). */
  clientIdPrefix?: PresentationClientIdPrefix;
  /** Whether the wallet redirects back (`same-device`) or the verifier polls (`cross-device`). */
  flowType?: PresentationFlowType;
  /** Retrieval method advertised for the `request_uri`. */
  requestUriMethod?: PresentationRequestUriMethod;
  /** Base URI the engagement is built on; omitted, the Relying Party applies its own default. */
  walletAuthBaseUri?: string;
}

/** Creates the engagement URI a wallet is given to start a presentation.
 *
 * @param baseURL - The local Relying Party base URL.
 * @param options - What the engagement must advertise.
 * @returns The engagement URI, carrying `client_id` and `request_uri`.
 */
export async function createPresentationRequestUri(
  baseURL: string,
  options: CreatePresentationRequestUriOptions = {}
): Promise<string> {
  const { clientIdPrefix, flowType = 'cross-device', requestUriMethod, walletAuthBaseUri } = options;
  const endpoint = new URL('/create-authorization-request', baseURL);

  const response = await httpsRequest<{ url: string }>({
    method: 'POST',
    hostname: endpoint.hostname,
    path: endpoint.pathname,
    port: endpoint.port,
    protocol: endpoint.protocol,
    headers: { 'content-type': 'application/json' },
    body: {
      dcqlQuery: createDefaultPresentationDcqlQuery(),
      flow_type: flowType,
      ...(clientIdPrefix ? { client_id_prefix: clientIdPrefix } : {}),
      ...(requestUriMethod ? { request_uri_method: requestUriMethod } : {}),
      ...(walletAuthBaseUri ? { wallet_auth_base_uri: walletAuthBaseUri } : {})
    },
    rejectUnauthorized: false
  });

  if (response.statusCode !== 200 || typeof response.data.url !== 'string') {
    throw new Error(`Unable to create presentation request (${response.statusCode ?? 'unknown'}): ${response.body}`);
  }

  return response.data.url;
}

export function extractPresentationCorrelationId(uri: string): string {
  const requestUri = new URL(uri).searchParams.get('request_uri');
  if (!requestUri) throw new Error('Presentation request URI does not contain a request_uri parameter');

  const state = new URL(requestUri).pathname.split('/').filter(Boolean).at(-1);
  if (!state) throw new Error('Presentation request request_uri does not contain a correlation identifier');
  return state;
}
