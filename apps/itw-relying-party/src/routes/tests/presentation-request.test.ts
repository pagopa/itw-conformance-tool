import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import presentationRequestRoute, { isValidEngagementUri } from '../presentation-request.js';

import type { FastifyInstance } from 'fastify';

const ENGAGEMENT_URI =
  'openid4vp://?client_id=https%3A%2F%2F127.0.0.1%3A3002&request_uri=https%3A%2F%2F127.0.0.1%3A3002%2Fauth%2Frequest%2F11111111-2222-4333-8444-555555555555';

async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(presentationRequestRoute);
  await app.ready();

  return app;
}

describe('isValidEngagementUri', () => {
  it('accepts any wallet scheme carrying the OpenID4VP engagement parameters', () => {
    expect(isValidEngagementUri(ENGAGEMENT_URI)).toBe(true);
    expect(isValidEngagementUri('mywallet://auth?client_id=x&request_uri=https%3A%2F%2Fy')).toBe(true);
    expect(isValidEngagementUri('https://wallet.example/auth?client_id=x&request_uri=https%3A%2F%2Fy')).toBe(true);
  });

  it('rejects a URI that is missing an engagement parameter', () => {
    expect(isValidEngagementUri('https://wallet.example/auth?client_id=x')).toBe(false);
    expect(isValidEngagementUri('https://wallet.example/auth?request_uri=y')).toBe(false);
  });

  it('rejects text that is not a URI', () => {
    expect(isValidEngagementUri('not a uri')).toBe(false);
  });
});

describe('GET /presentation-request', () => {
  it('renders the engagement as a scannable QR page', async () => {
    const app = await buildApp();

    const response = await app.inject({
      method: 'GET',
      url: '/presentation-request',
      query: { uri: ENGAGEMENT_URI }
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/html');
    expect(response.body).toContain('<svg');
    // The URI reaches the page only in escaped form, never as raw markup.
    expect(response.body).toContain('&amp;request_uri=');
    expect(response.body).not.toContain(`>${ENGAGEMENT_URI}<`);

    await app.close();
  });

  it('rejects an engagement URI that this Relying Party could not have produced', async () => {
    const app = await buildApp();

    const response = await app.inject({
      method: 'GET',
      url: '/presentation-request',
      query: { uri: 'https://wallet.example/auth' }
    });

    expect(response.statusCode).toBe(400);

    await app.close();
  });

  it('rejects a request without the uri parameter', async () => {
    const app = await buildApp();

    const response = await app.inject({ method: 'GET', url: '/presentation-request' });

    expect(response.statusCode).toBe(400);

    await app.close();
  });
});
