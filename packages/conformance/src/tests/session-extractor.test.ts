import { describe, expect, it } from 'vitest';

import { extractIssuerSessionId, extractRpSessionId } from '../utils/session-extractor.js';

const VALID_UUID = '550e8400-e29b-41d4-a716-446655440000';
const VALID_REQUEST_URI = `urn:ietf:params:oauth:request_uri:${VALID_UUID}`;

describe('extractIssuerSessionId', () => {
  it('extracts the UUID from a valid request_uri', () => {
    expect(extractIssuerSessionId(VALID_REQUEST_URI)).toBe(VALID_UUID);
  });

  it('is case-insensitive for the UUID hex digits', () => {
    const upperCaseUri = `urn:ietf:params:oauth:request_uri:${VALID_UUID.toUpperCase()}`;
    expect(extractIssuerSessionId(upperCaseUri)).toBe(VALID_UUID.toUpperCase());
  });

  // The prefix check is intentionally case-sensitive: the issuer always generates
  // request_uri values with a lowercase URN prefix and the wallet returns them verbatim.
  // A case-insensitive match would accept values that cannot be looked up in the PAR store.
  it('returns null for an uppercase URN prefix (prefix match is case-sensitive by design)', () => {
    const upperPrefixUri = `URN:IETF:PARAMS:OAUTH:REQUEST_URI:${VALID_UUID}`;
    expect(extractIssuerSessionId(upperPrefixUri)).toBeNull();
  });

  it('returns null when the prefix is missing', () => {
    expect(extractIssuerSessionId(VALID_UUID)).toBeNull();
  });

  it('returns null when the URN prefix is wrong', () => {
    expect(extractIssuerSessionId(`urn:ietf:params:oauth:request:${VALID_UUID}`)).toBeNull();
  });

  it('returns null when the UUID portion is empty', () => {
    expect(extractIssuerSessionId('urn:ietf:params:oauth:request_uri:')).toBeNull();
  });

  it('returns null when the UUID portion is malformed', () => {
    expect(extractIssuerSessionId('urn:ietf:params:oauth:request_uri:not-a-uuid')).toBeNull();
  });

  it('returns null when the UUID has the wrong number of segments', () => {
    expect(extractIssuerSessionId('urn:ietf:params:oauth:request_uri:550e8400-e29b-41d4-a716')).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(extractIssuerSessionId('')).toBeNull();
  });

  it('returns null when there are trailing characters after the UUID', () => {
    expect(extractIssuerSessionId(`${VALID_REQUEST_URI}/extra`)).toBeNull();
  });
});

describe('extractRpSessionId', () => {
  it('returns the state as-is when it is a valid UUID', () => {
    expect(extractRpSessionId(VALID_UUID)).toBe(VALID_UUID);
  });

  it('is case-insensitive for the UUID hex digits', () => {
    const upper = VALID_UUID.toUpperCase();
    expect(extractRpSessionId(upper)).toBe(upper);
  });

  it('returns null for a non-UUID string', () => {
    expect(extractRpSessionId('some-random-state')).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(extractRpSessionId('')).toBeNull();
  });

  it('returns null for a UUID with extra trailing content', () => {
    expect(extractRpSessionId(`${VALID_UUID}-extra`)).toBeNull();
  });
});
