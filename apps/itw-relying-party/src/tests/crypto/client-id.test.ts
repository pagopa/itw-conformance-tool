import { describe, expect, it } from 'vitest';

import { extractClientId } from '../../crypto/client-id.js';

describe('extractClientId', () => {
  it('returns the baseUrl unchanged when there is no trailing slash', () => {
    expect(extractClientId('http://localhost:8080')).toBe('http://localhost:8080');
  });

  it('strips a single trailing slash', () => {
    expect(extractClientId('http://localhost:8080/')).toBe('http://localhost:8080');
  });

  it('strips multiple trailing slashes', () => {
    expect(extractClientId('http://localhost:8080///')).toBe('http://localhost:8080');
  });

  it('preserves internal path segments without trailing slash', () => {
    expect(extractClientId('https://rp.example.com/conformance-tool')).toBe('https://rp.example.com/conformance-tool');
  });

  it('strips trailing slash from a URL with path', () => {
    expect(extractClientId('https://rp.example.com/conformance-tool/')).toBe('https://rp.example.com/conformance-tool');
  });

  it('handles HTTPS URLs', () => {
    expect(extractClientId('https://rp.example.com')).toBe('https://rp.example.com');
  });

  it('returns the same string when called twice with the same input (idempotent)', () => {
    const input = 'https://rp.example.com';
    expect(extractClientId(extractClientId(input))).toBe(extractClientId(input));
  });
});
