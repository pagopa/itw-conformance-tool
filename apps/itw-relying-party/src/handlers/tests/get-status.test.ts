import { randomUUID } from 'node:crypto';

import FastifyCookie from '@fastify/cookie';
import FastifySensible from '@fastify/sensible';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import getStatusRoute from '../../routes/get-status.js';
import { USER_AGENT_SESSION_COOKIE } from '../../utils/user-agent-session.js';

/** Identifier the browser that started the flow carries in its session cookie. */
const USER_AGENT_SESSION_ID = 'user-agent-session-id';

interface StoredRequestObject {
  flowType?: 'cross-device' | 'same-device';
  redirectUri?: string;
  status: string;
  userAgentSessionId?: string;
  values?: Record<string, null | string>[];
}

async function buildApp(stored: StoredRequestObject | undefined) {
  const app = Fastify();
  const deleted: string[] = [];

  app.decorate('repository', {
    requestObject: {
      delete: (requestObjectId: string) => {
        deleted.push(requestObjectId);
      },
      get: () => {
        if (!stored) throw new Error('Request object not found');
        // Bound to the polling browser unless a case says otherwise: that is what
        // `create-authorization-request` writes for every flow.
        return { flowType: 'cross-device', userAgentSessionId: USER_AGENT_SESSION_ID, ...stored };
      }
    }
  });

  await app.register(FastifySensible);
  await app.register(FastifyCookie);
  await app.register(getStatusRoute);
  await app.ready();

  return { app, deleted };
}

/**
 * Polls the status endpoint the way the browser holding the session cookie
 * would. Pass `null` to poll from a user-agent carrying no cookie at all.
 */
function poll(
  app: Awaited<ReturnType<typeof buildApp>>['app'],
  state: string,
  userAgentSessionId: string | null = USER_AGENT_SESSION_ID
) {
  return app.inject({
    method: 'GET',
    url: `/status/${state}`,
    ...(userAgentSessionId ? { cookies: { [USER_AGENT_SESSION_COOKIE]: userAgentSessionId } } : {})
  });
}

describe('GET /status/:state', () => {
  it('returns the verified presentation to the browser that started the flow', async () => {
    const state = randomUUID();
    const values = [{ given_name: 'Mario' }];
    const { app } = await buildApp({ redirectUri: `https://rp.example.org/callback`, status: 'verified', values });

    const response = await poll(app, state);

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ redirect_uri: 'success.html?response_code=success', values });

    await app.close();
  });

  describe('user-agent session binding', () => {
    it('does not disclose the presented values to another user session', async () => {
      const state = randomUUID();
      const { app, deleted } = await buildApp({
        redirectUri: `https://rp.example.org/callback`,
        status: 'verified',
        values: [{ given_name: 'Mario' }]
      });

      // `state` is public — it travels in the `request_uri` the engagement QR
      // encodes — so knowing it must not be enough to read the disclosed claims.
      const response = await poll(app, state, 'another-session');

      expect(response.statusCode).toBe(404);
      expect(response.body, 'the disclosed claims must not reach an unbound caller').not.toContain('Mario');
      expect(deleted, 'an unbound caller must not reach the branches that delete the session').toHaveLength(0);

      await app.close();
    });

    it('does not disclose the presented values to a caller carrying no cookie', async () => {
      const state = randomUUID();
      const { app } = await buildApp({
        redirectUri: `https://rp.example.org/callback`,
        status: 'verified',
        values: [{ given_name: 'Mario' }]
      });

      const response = await poll(app, state, null);

      expect(response.statusCode).toBe(404);
      expect(response.body).not.toContain('Mario');

      await app.close();
    });

    it('binds the cross-device flow too, where the polling browser started the flow', async () => {
      const state = randomUUID();
      const { app } = await buildApp({
        flowType: 'cross-device',
        redirectUri: `https://rp.example.org/callback`,
        status: 'verified'
      });

      // Unlike `/callback`, which cannot be bound in Cross Device because the
      // originating browser is on another device, the browser polling here is
      // always the one that created the request — it is displaying the QR code.
      expect((await poll(app, state, 'another-session')).statusCode).toBe(404);
      expect((await poll(app, state)).statusCode).toBe(200);

      await app.close();
    });

    it('answers an unknown state exactly as one belonging to another session', async () => {
      const { app: unknownApp } = await buildApp(undefined);
      const { app: otherSessionApp } = await buildApp({ status: 'pending' });

      const unknown = await poll(unknownApp, randomUUID());
      const otherSession = await poll(otherSessionApp, randomUUID(), 'another-session');

      // Identical answers, so polling cannot be used to discover which states
      // exist.
      expect(unknown.statusCode).toBe(404);
      expect(otherSession.statusCode).toBe(404);
      expect(unknown.body).toBe(otherSession.body);

      await unknownApp.close();
      await otherSessionApp.close();
    });

    it('does not let an unbound caller delete a terminal session', async () => {
      const state = randomUUID();
      const { app, deleted } = await buildApp({ status: 'expired' });

      // The terminal branches delete the row, so an unbound poll would otherwise
      // let anyone holding `state` destroy the session the real browser polls.
      expect((await poll(app, state, 'another-session')).statusCode).toBe(404);
      expect(deleted).toHaveLength(0);

      expect((await poll(app, state)).statusCode).toBe(200);
      expect(deleted).toEqual([state]);

      await app.close();
    });
  });
});
