import { describe, it, expect, afterEach, beforeEach } from 'vitest';

import statusRoute from '../../routes/status.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

describe('GET /status/:state', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  beforeEach(async () => {
    ctx = await buildRpRouteApp(statusRoute);
  });

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('returns 404 when session does not exist', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/status/unknown-state' });
    expect(res.statusCode).toBe(404);
  });

  it('returns pending response code for a new session', async () => {
    await ctx.sessionService.create({
      id: 'pending-session',
      jwt: 'a.b.c',
      flowType: 'cross-device',
      ttlMs: 300_000
    });

    const res = await ctx.app.inject({ method: 'GET', url: '/status/pending-session' });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ redirect_uri: string }>();
    expect(body.redirect_uri).toContain('response_code=pending');
  });

  it('returns checking response code after auth-request is fetched', async () => {
    await ctx.sessionService.create({ id: 'check-session', jwt: 'a.b.c', flowType: 'cross-device', ttlMs: 300_000 });
    await ctx.sessionService.update('check-session', 'checking');

    const res = await ctx.app.inject({ method: 'GET', url: '/status/check-session' });
    expect(res.json<{ redirect_uri: string }>().redirect_uri).toContain('response_code=checking');
  });

  it('appends response_code=success for a verified session when missing', async () => {
    const redirectUri = 'http://localhost:8080/success.html';
    await ctx.sessionService.create({ id: 'verified-session', jwt: 'a.b.c', flowType: 'cross-device', ttlMs: 300_000 });
    await ctx.sessionService.update('verified-session', 'verified', { redirectUri });

    const res = await ctx.app.inject({ method: 'GET', url: '/status/verified-session' });
    const body = res.json<{ redirect_uri: string }>();
    expect(body.redirect_uri).toBe('http://localhost:8080/success.html?response_code=success');
  });

  it('preserves redirect_uri if response_code is already present for a verified session', async () => {
    const redirectUri = 'http://localhost:8080/success.html?response_code=abc123';
    await ctx.sessionService.create({
      id: 'verified-session-existing-code',
      jwt: 'a.b.c',
      flowType: 'cross-device',
      ttlMs: 300_000
    });
    await ctx.sessionService.update('verified-session-existing-code', 'verified', { redirectUri });

    const res = await ctx.app.inject({ method: 'GET', url: '/status/verified-session-existing-code' });
    const body = res.json<{ redirect_uri: string }>();
    expect(body.redirect_uri).toBe(redirectUri);
  });

  it('returns rejected redirect for a rejected session', async () => {
    await ctx.sessionService.create({ id: 'rejected-session', jwt: 'a.b.c', flowType: 'cross-device', ttlMs: 300_000 });
    await ctx.sessionService.update('rejected-session', 'rejected');

    const res = await ctx.app.inject({ method: 'GET', url: '/status/rejected-session' });
    expect(res.json<{ redirect_uri: string }>().redirect_uri).toContain('rejected-error.html');
  });

  it('returns denied redirect for a denied session', async () => {
    await ctx.sessionService.create({ id: 'denied-session', jwt: 'a.b.c', flowType: 'cross-device', ttlMs: 300_000 });
    await ctx.sessionService.update('denied-session', 'denied');

    const res = await ctx.app.inject({ method: 'GET', url: '/status/denied-session' });
    expect(res.json<{ redirect_uri: string }>().redirect_uri).toContain('error.html');
  });
});
