import { describe, it, expect, afterEach } from 'vitest';

import requestObjectRoute from '../../routes/request-object.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

function requireValue<T>(value: T | null | undefined, message: string): T {
  if (value === null || value === undefined || (typeof value === 'string' && value.length === 0)) {
    throw new Error(message);
  }
  return value;
}

const VALID_DCQL_BODY = {
  dcqlQuery: {
    credentials: [{ id: 'pid', format: 'dc+sd-jwt' }]
  },
  flow_type: 'cross-device'
};

describe('POST /request-object', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('returns 200 with a wallet URL on valid DCQL', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: VALID_DCQL_BODY
    });

    expect(res.statusCode).toBe(200);
    const body = res.json<{ url: string }>();
    expect(typeof body.url).toBe('string');

    const url = new URL(body.url);
    expect(url.searchParams.has('request_uri')).toBe(true);
    expect(url.searchParams.has('client_id')).toBe(true);
    expect(url.searchParams.has('state')).toBe(true);

    const state = requireValue(url.searchParams.get('state'), 'Missing state in wallet URL');

    const session = requireValue(await ctx.sessionService.get(state), 'Missing saved session');

    const [headerB64, payloadB64] = session.jwt.split('.');
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString()) as {
      typ: string;
      x5c?: string[];
    };
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString()) as {
      client_id: string;
      client_metadata?: {
        jwks?: { keys?: Array<{ kid?: string }> };
      };
      nonce: string;
      response_uri: string;
      state: string;
    };

    expect(header.typ).toBe('oauth-authz-req+jwt');
    expect(header.x5c).toEqual(['CERT']);
    expect(payload.client_id).toBe('x509_hash:http://localhost:8080');
    expect(payload.client_metadata?.jwks?.keys?.[0]?.kid).toBeTruthy();
    expect(payload.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(payload.response_uri).toBe('http://localhost:8080/auth/response');
    expect(payload.state).toBe(state);
  });

  it('request_uri points to /auth/request/:state', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: VALID_DCQL_BODY
    });
    const { url } = res.json<{ url: string }>();
    const parsedUrl = new URL(url);
    const requestUri = requireValue(parsedUrl.searchParams.get('request_uri'), 'Missing request_uri in wallet URL');
    expect(requestUri).toMatch(/\/auth\/request\/[0-9a-f-]+$/);
  });

  it('returns 400 when dcqlQuery is missing', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: { flow_type: 'cross-device' }
    });
    expect(res.statusCode).toBe(400);
  });

  it('accepts custom wallet_auth_base_uri', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: {
        ...VALID_DCQL_BODY,
        wallet_auth_base_uri: 'https://wallet.example.com/auth'
      }
    });
    expect(res.statusCode).toBe(200);
    const { url } = res.json<{ url: string }>();
    expect(url).toMatch(/^https:\/\/wallet\.example\.com\/auth/);
  });
});
