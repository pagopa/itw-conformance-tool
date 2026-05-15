import { describe, expect, it } from 'vitest';

import { generateFakeUser, generateFiscalCode } from '../faker.js';

describe('generateFakeUser', () => {
  it('returns a deterministic user for the same clientId', () => {
    const user1 = generateFakeUser('client-abc');
    const user2 = generateFakeUser('client-abc');

    expect(user1).toEqual(user2);
  });

  it('returns different users for different clientIds', () => {
    const user1 = generateFakeUser('client-a');
    const user2 = generateFakeUser('client-b');

    expect(user1.fiscalCode).not.toBe(user2.fiscalCode);
  });

  it('has the expected shape', () => {
    const user = generateFakeUser('test-client');

    expect(user).toMatchObject({
      birthDate: expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/),
      birthPlace: expect.any(String),
      documentNumber: expect.stringMatching(/^[A-Z0-9]{18}$/),
      familyName: expect.any(String),
      fiscalCode: expect.stringMatching(/^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$/),
      givenName: expect.any(String),
      id: expect.stringMatching(/^[0-9a-f-]{36}$/)
    });
  });
});

describe('generateFiscalCode', () => {
  it('generates a 16-character alphanumeric code', () => {
    const code = generateFiscalCode({
      birthDate: '1990-01-15',
      familyName: 'Rossi',
      givenName: 'Mario'
    });

    expect(code).toHaveLength(16);
    expect(code).toMatch(/^[A-Z0-9]{16}$/);
  });

  it('produces consistent output for the same input', () => {
    const input = { birthDate: '1985-06-20', familyName: 'Bianchi', givenName: 'Lucia' };

    expect(generateFiscalCode(input)).toBe(generateFiscalCode(input));
  });

  it('handles names with accented characters', () => {
    const code = generateFiscalCode({
      birthDate: '1975-03-10',
      familyName: 'Conté',
      givenName: 'André'
    });

    expect(code).toHaveLength(16);
    expect(code).toMatch(/^[A-Z0-9]{16}$/);
  });
});
