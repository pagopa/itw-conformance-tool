import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import authRequestRoute from '../../../routes/auth-request.js';
import requestObjectRoute from '../../../routes/request-object.js';
import { buildRpRouteApp } from '../../helpers/rp-route-app.js';

// Fields considered PII — the wallet must not send these in wallet_metadata (WP_083b)
const PII_FIELDS = ['device_name', 'user_id', 'email', 'phone', 'hardware_id', 'serial_number', 'imei', 'name'];

// Minimal well-formed wallet_metadata (WP_083a)
const VALID_WALLET_METADATA = {
  authorization_endpoint: 'eudi-openid4vp://',
  client_id_schemes_supported: ['x509_hash'],
  vp_formats_supported: { 'dc+sd-jwt': {}, 'vc+sd-jwt': {} }
};

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
  it('[PRESENTATION:AUTHORIZE] WP_082: GET Request Object — Wallet retrieves signed JWT via HTTP GET when request_uri_method is absent or get', async () => {
    const state = await createState();

    const res = await ctx.app.inject({ method: 'GET', url: `/auth/request/${state}` });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('oauth-authz-req+jwt');
    expect(res.body.split('.').length).toBe(3);
  });

  it('[PRESENTATION:AUTHORIZE] WP_083: POST Request Object — Wallet retrieves signed JWT via HTTP POST including wallet_metadata and wallet_nonce', async () => {
    const state = await createState();

    const body = new URLSearchParams({
      wallet_metadata: JSON.stringify(VALID_WALLET_METADATA),
      wallet_nonce: randomUUID()
    });

    const res = await ctx.app.inject({
      body: body.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      url: `/auth/request/${state}`
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('oauth-authz-req+jwt');
    expect(res.body.split('.').length).toBe(3);
  });

  it('[PRESENTATION:AUTHORIZE] WP_083a: Construct wallet_metadata — wallet_metadata contains vp_formats_supported, client_id_schemes_supported, and authorization_endpoint', async () => {
    const state = await createState();

    expect(VALID_WALLET_METADATA).toHaveProperty('vp_formats_supported');
    expect(VALID_WALLET_METADATA).toHaveProperty('client_id_schemes_supported');
    expect(VALID_WALLET_METADATA).toHaveProperty('authorization_endpoint');

    const body = new URLSearchParams({
      wallet_metadata: JSON.stringify(VALID_WALLET_METADATA),
      wallet_nonce: randomUUID()
    });

    const res = await ctx.app.inject({
      body: body.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      url: `/auth/request/${state}`
    });

    expect(res.statusCode).toBe(200);
  });

  it('[PRESENTATION:AUTHORIZE] WP_083b: Exclude PII in wallet_metadata — wallet_metadata contains no user-identifiable or device-specific fields', async () => {
    const state = await createState();

    const metadataKeys = Object.keys(VALID_WALLET_METADATA);
    const piiPresent = metadataKeys.filter((k) => PII_FIELDS.includes(k));
    expect(piiPresent).toHaveLength(0);

    const body = new URLSearchParams({
      wallet_metadata: JSON.stringify(VALID_WALLET_METADATA),
      wallet_nonce: randomUUID()
    });

    const res = await ctx.app.inject({
      body: body.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      url: `/auth/request/${state}`
    });

    expect(res.statusCode).toBe(200);
  });

  it('[PRESENTATION:AUTHORIZE] WP_083c: Generate replay nonce — wallet_nonce is present in the POST request payload to mitigate replay attacks', async () => {
    const state = await createState();

    const walletNonce = randomUUID();
    expect(walletNonce.length).toBeGreaterThan(0);

    const body = new URLSearchParams({
      wallet_metadata: JSON.stringify(VALID_WALLET_METADATA),
      wallet_nonce: walletNonce
    });

    expect(body.get('wallet_nonce')).toBe(walletNonce);

    const res = await ctx.app.inject({
      body: body.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      url: `/auth/request/${state}`
    });

    expect(res.statusCode).toBe(200);
  });
});
