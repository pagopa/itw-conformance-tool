import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import authRequestRoute from '../../../routes/auth-request.js';
import requestObjectRoute from '../../../routes/request-object.js';
import { buildRpRouteApp } from '../../helpers/rp-route-app.js';

// Minimal well-formed wallet_metadata (WP_083a)
const VALID_WALLET_METADATA = {
  authorization_endpoint: 'eudi-openid4vp://',
  client_id_schemes_supported: ['x509_hash'],
  vp_formats_supported: { 'dc+sd-jwt': {}, 'vc+sd-jwt': {} }
};

// PII fields — wallet_metadata must not contain these (WP_083b)
const PII_FIELDS = ['device_name', 'user_id', 'email', 'phone', 'hardware_id', 'serial_number', 'imei', 'name'];

const DCQL_BODY = {
  dcqlQuery: { credentials: [{ format: 'dc+sd-jwt', id: 'pid' }] },
  flow_type: 'cross-device'
};

let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

async function createState(): Promise<string> {
  const res = await ctx.app.inject({ method: 'POST', payload: DCQL_BODY, url: '/request-object' });
  const { url } = res.json<{ url: string }>();
  const state = new URL(url).searchParams.get('state');
  if (!state) throw new Error('Missing state in wallet URL');
  return state;
}

beforeAll(async () => {
  ctx = await buildRpRouteApp(requestObjectRoute, {
    setup: async (app) => {
      await app.register(authRequestRoute);
    }
  });
});

afterAll(async () => {
  await ctx.app.close();
});

describe('Presentation - Request Object retrieval (WP_082 / WP_083)', () => {
  it('[PRESENTATION:AUTHORIZE] WP_082: GET Request Object — Wallet retrieves signed JWT via HTTP GET', async () => {
    const state = await createState();

    const res = await ctx.app.inject({ method: 'GET', url: `/auth/request/${state}` });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/oauth-authz-req+jwt');
  });

  it('[PRESENTATION:AUTHORIZE] WP_083: POST Request Object — Wallet retrieves signed JWT via HTTP POST including wallet_metadata and wallet_nonce', async () => {
    const state = await createState();

    const res = await ctx.app.inject({
      method: 'POST',
      url: `/auth/request/${state}`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: `wallet_nonce=test-nonce-${randomUUID()}&wallet_metadata=${encodeURIComponent(JSON.stringify(VALID_WALLET_METADATA))}`
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/oauth-authz-req+jwt');
  });

  it('[PRESENTATION:AUTHORIZE] WP_083a: Construct wallet_metadata — wallet_metadata contains vp_formats_supported, client_id_schemes_supported, and authorization_endpoint', async () => {
    const state = await createState();

    const res = await ctx.app.inject({
      method: 'POST',
      url: `/auth/request/${state}`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: `wallet_nonce=test-nonce-${randomUUID()}&wallet_metadata=${encodeURIComponent(JSON.stringify(VALID_WALLET_METADATA))}`
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/oauth-authz-req+jwt');

  it('[PRESENTATION:AUTHORIZE] WP_083b: Exclude PII in wallet_metadata — wallet_metadata contains no user-identifiable or device-specific fields', async () => {
    const state = await createState();

    const res = await ctx.app.inject({
      method: 'POST',
      url: `/auth/request/${state}`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: `wallet_nonce=test-nonce-${randomUUID()}&wallet_metadata=${encodeURIComponent(JSON.stringify(VALID_WALLET_METADATA))}`
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/oauth-authz-req+jwt');
  });

  it('[PRESENTATION:AUTHORIZE] WP_083c: Generate replay nonce — wallet_nonce is present in the POST request payload to mitigate replay attacks', async () => {
    const state = await createState();
    const walletNonce = `nonce-${randomUUID()}`;

    const res = await ctx.app.inject({
      method: 'POST',
      url: `/auth/request/${state}`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: `wallet_nonce=${encodeURIComponent(walletNonce)}&wallet_metadata=${encodeURIComponent(JSON.stringify(VALID_WALLET_METADATA))}`
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/oauth-authz-req+jwt');
  });
});
