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

export async function createPresentationRequestUri(baseURL: string): Promise<string> {
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
      flow_type: 'cross-device'
    },
    rejectUnauthorized: false
  });

  return response.data.url;
}

export function extractPresentationCorrelationId(uri: string): string {
  const state = new URL(uri).searchParams.get('state');
  if (!state) throw new Error('Presentation request URI does not contain a state parameter');
  return state;
}
