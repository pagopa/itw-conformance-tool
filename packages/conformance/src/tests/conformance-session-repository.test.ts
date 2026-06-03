import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DatabaseClient } from '@itw-conformance-tool/database';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SqliteConformanceSessionRepository } from '../repository.js';

import type { ConformanceCheck, ConformanceSession } from '@itw-conformance-tool/database';

function makeTmpDir(): string {
  return join(tmpdir(), `itw-conformance-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

function makeSession(overrides: Partial<ConformanceSession> = {}): ConformanceSession {
  return {
    sessionId: 'aaaaaaaa-0000-1111-2222-333344445555',
    startedAt: new Date().toISOString(),
    status: 'OPEN',
    checks: [],
    ...overrides
  };
}

function makeCheck(overrides: Partial<ConformanceCheck> = {}): ConformanceCheck {
  return {
    requirementId: 'IT-WALLET-1.4-§4.2.1',
    description: 'PAR request contains a valid Wallet Attestation JWT',
    step: 'PAR',
    phase: 'ISSUANCE',
    result: 'PASS',
    timestamp: new Date().toISOString(),
    ...overrides
  };
}

describe('SqliteConformanceSessionRepository', () => {
  let client: DatabaseClient;
  let repo: SqliteConformanceSessionRepository;

  beforeEach(() => {
    client = new DatabaseClient({ dataDir: makeTmpDir(), cleanupIntervalMs: 999_999 });
    repo = new SqliteConformanceSessionRepository(client.db);
  });

  afterEach(() => {
    client.close();
  });

  describe('create', () => {
    it('persists a new OPEN session with no checks', async () => {
      const session = makeSession();
      await repo.create(session);

      const result = await repo.get(session.sessionId);
      expect(result).not.toBeNull();
      expect(result?.sessionId).toBe(session.sessionId);
      expect(result?.startedAt).toBe(session.startedAt);
      expect(result?.status).toBe('OPEN');
      expect(result?.closedAt).toBeUndefined();
      expect(result?.checks).toEqual([]);
    });

    it('persists a session with pre-populated checks', async () => {
      const check = makeCheck();
      const session = makeSession({ checks: [check] });
      await repo.create(session);

      const result = await repo.get(session.sessionId);
      expect(result?.checks).toHaveLength(1);
      expect(result?.checks[0]?.requirementId).toBe(check.requirementId);
    });

    it('persists a session with a closedAt timestamp', async () => {
      const closedAt = new Date().toISOString();
      const session = makeSession({ status: 'PASSED', closedAt });
      await repo.create(session);

      const result = await repo.get(session.sessionId);
      expect(result?.closedAt).toBe(closedAt);
      expect(result?.status).toBe('PASSED');
    });
  });

  describe('get', () => {
    it('returns null for a non-existent sessionId', async () => {
      const result = await repo.get('00000000-0000-0000-0000-000000000000');
      expect(result).toBeNull();
    });

    it('round-trips all ConformanceCheck fields', async () => {
      const check: ConformanceCheck = {
        requirementId: 'IT-WALLET-1.4-§4.3.2',
        description: 'Token request uses DPoP proof',
        step: 'TOKEN',
        phase: 'ISSUANCE',
        result: 'FAIL',
        timestamp: '2026-06-03T10:00:00.000Z',
        httpStatus: 400,
        errorMessage: 'invalid_dpop_proof'
      };
      const session = makeSession({ checks: [check] });
      await repo.create(session);

      const result = await repo.get(session.sessionId);
      expect(result?.checks[0]).toEqual(check);
    });
  });

  describe('appendCheck', () => {
    it('appends a check to an existing session', async () => {
      await repo.create(makeSession());
      const check = makeCheck();
      await repo.appendCheck(makeSession().sessionId, check);

      const result = await repo.get(makeSession().sessionId);
      expect(result?.checks).toHaveLength(1);
      expect(result?.checks[0]?.step).toBe('PAR');
    });

    it('appends multiple checks in order', async () => {
      const sessionId = 'bbbbbbbb-0000-1111-2222-333344445555';
      await repo.create(makeSession({ sessionId }));

      const check1 = makeCheck({ step: 'PAR', result: 'PASS' });
      const check2 = makeCheck({ step: 'AUTHORIZE', result: 'PASS' });
      const check3 = makeCheck({ step: 'TOKEN', result: 'FAIL', httpStatus: 400 });

      await repo.appendCheck(sessionId, check1);
      await repo.appendCheck(sessionId, check2);
      await repo.appendCheck(sessionId, check3);

      const result = await repo.get(sessionId);
      expect(result?.checks).toHaveLength(3);
      expect(result?.checks[0]?.step).toBe('PAR');
      expect(result?.checks[1]?.step).toBe('AUTHORIZE');
      expect(result?.checks[2]?.step).toBe('TOKEN');
    });

    it('is a no-op for a non-existent sessionId', async () => {
      await expect(repo.appendCheck('nonexistent-id', makeCheck())).resolves.not.toThrow();
    });

    it('correctly persists optional fields on ConformanceCheck', async () => {
      const sessionId = 'cccccccc-0000-1111-2222-333344445555';
      await repo.create(makeSession({ sessionId }));

      const check = makeCheck({
        result: 'FAIL',
        httpStatus: 422,
        errorMessage: 'missing_dpop_proof'
      });
      await repo.appendCheck(sessionId, check);

      const result = await repo.get(sessionId);
      expect(result?.checks[0]?.httpStatus).toBe(422);
      expect(result?.checks[0]?.errorMessage).toBe('missing_dpop_proof');
    });
  });

  describe('close', () => {
    it('closes a session with status PASSED', async () => {
      const sessionId = 'dddddddd-0000-1111-2222-333344445555';
      await repo.create(makeSession({ sessionId }));

      await repo.close(sessionId, 'PASSED');

      const result = await repo.get(sessionId);
      expect(result?.status).toBe('PASSED');
      expect(result?.closedAt).toBeDefined();
      expect(typeof result?.closedAt).toBe('string');
    });

    it('closes a session with status FAILED', async () => {
      const sessionId = 'eeeeeeee-0000-1111-2222-333344445555';
      await repo.create(makeSession({ sessionId }));

      await repo.close(sessionId, 'FAILED');

      const result = await repo.get(sessionId);
      expect(result?.status).toBe('FAILED');
      expect(result?.closedAt).toBeDefined();
    });

    it('closes a session with status INCOMPLETE', async () => {
      const sessionId = 'ffffffff-0000-1111-2222-333344445555';
      await repo.create(makeSession({ sessionId }));

      await repo.close(sessionId, 'INCOMPLETE');

      const result = await repo.get(sessionId);
      expect(result?.status).toBe('INCOMPLETE');
      expect(result?.closedAt).toBeDefined();
    });

    it('sets closedAt to a valid ISO 8601 timestamp', async () => {
      const sessionId = '11111111-0000-1111-2222-333344445555';
      await repo.create(makeSession({ sessionId }));

      const before = new Date().toISOString();
      await repo.close(sessionId, 'PASSED');
      const after = new Date().toISOString();

      const result = await repo.get(sessionId);
      expect(result?.closedAt).toBeDefined();
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result!.closedAt! >= before).toBe(true);
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result!.closedAt! <= after).toBe(true);
    });

    it('preserves existing checks when closing', async () => {
      const sessionId = '22222222-0000-1111-2222-333344445555';
      await repo.create(makeSession({ sessionId }));
      await repo.appendCheck(sessionId, makeCheck({ step: 'PAR' }));
      await repo.appendCheck(sessionId, makeCheck({ step: 'AUTHORIZE' }));

      await repo.close(sessionId, 'PASSED');

      const result = await repo.get(sessionId);
      expect(result?.checks).toHaveLength(2);
    });
  });
});
