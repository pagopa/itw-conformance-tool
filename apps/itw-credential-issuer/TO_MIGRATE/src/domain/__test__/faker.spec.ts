import { describe, expect, it } from 'vitest';

import { generateFakeUser, generateFiscalCode } from '../faker';

describe('generateFiscalCode', () => {
  it('should derive a valid fiscal code for a known male subject', () => {
    const fiscalCode = generateFiscalCode({
      birthDate: '1980-01-01',
      familyName: 'Rossi',
      givenName: 'Mario'
    });

    expect(fiscalCode).toBe('RSSMRA80A01H501U');
  });

  it('should handle names with accents and short consonant groups', () => {
    const fiscalCode = generateFiscalCode({
      birthDate: '1976-06-29',
      familyName: 'Foà',
      givenName: 'Elia'
    });

    expect(fiscalCode).toBe('FOALEI76H29H501J');
  });
});

describe('generateFakeUser', () => {
  it('should generate users with a derived fiscal code', () => {
    const user = generateFakeUser('test-client-id');

    expect(user.givenName.length).toBeGreaterThan(0);
    expect(user.familyName.length).toBeGreaterThan(0);
    expect(user.birthDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(user.documentNumber).toMatch(/^[A-Z0-9]{18}$/);
    expect(user.fiscalCode).toMatch(/^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$/);
    expect(user.fiscalCode.startsWith('FISCAL_CODE')).toBe(false);
  });

  it('should return the same user for the same client_id (deterministic)', () => {
    const clientId = 'wallet-client-abc123';

    const user1 = generateFakeUser(clientId);
    const user2 = generateFakeUser(clientId);

    expect(user1).toEqual(user2);
  });

  it('should return different users for different client_ids', () => {
    const user1 = generateFakeUser('wallet-client-aaa');
    const user2 = generateFakeUser('wallet-client-bbb');

    expect(user1).not.toEqual(user2);
  });
});
