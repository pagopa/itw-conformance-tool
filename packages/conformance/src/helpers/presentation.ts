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

export async function createPresentationRequestUri(
  baseURL: string,
  flowType: PresentationFlowType = 'cross-device',
  requestUriMethod?: PresentationRequestUriMethod
): Promise<string> {
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
      ...(requestUriMethod ? { request_uri_method: requestUriMethod } : {})
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
