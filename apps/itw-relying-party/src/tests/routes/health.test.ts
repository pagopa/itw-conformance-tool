import { describe, it, expect, afterEach } from 'vitest';

import healthRoute from '../../routes/health.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

describe('GET /health', () => {
  let app: Awaited<ReturnType<typeof buildRpRouteApp>>['app'];

  afterEach(async () => {
    await app?.close();
  });

  it('returns status ok', async () => {
    ({ app } = await buildRpRouteApp(healthRoute));
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });
});
