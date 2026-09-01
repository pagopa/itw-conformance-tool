import { describe, expect, it } from 'vitest';

import { isUriUnderAttestedPrefix } from '../url.js';

const RP = 'https://rp.example.org';

describe('isUriUnderAttestedPrefix', () => {
  describe('the live Relying Party endpoints against what it attests', () => {
    // Each row is a real pairing from the Relying Party: the entry published in
    // `metadata.openid_credential_verifier`, and the URI a wallet is actually
    // handed. A wallet applying this rule must accept every one of them.
    it.each([
      ['request_uri', `${RP}/auth/request`, `${RP}/auth/request/11111111-2222-4333-8444-555555555555`],
      ['response_uri', `${RP}/auth/response`, `${RP}/auth/response?session_id=11111111-2222-4333-8444-555555555555`],
      ['redirect_uri', `${RP}/callback`, `${RP}/callback?state=a-state&response_code=abc123`]
    ])('accepts the live %s', (_name, attested, live) => {
      expect(isUriUnderAttestedPrefix(live, attested)).toBe(true);
    });

    // The same three live URIs against the paths the WP_081, WP_091a and WP_094a
    // faults publish instead. Every one must be refused, or the fault proves
    // nothing and the scenario silently passes.
    it.each([
      ['WP_081', `${RP}/auth/request-unattested`, `${RP}/auth/request/11111111-2222-4333-8444-555555555555`],
      [
        'WP_091a',
        `${RP}/auth/response-unattested`,
        `${RP}/auth/response?session_id=11111111-2222-4333-8444-555555555555`
      ],
      ['WP_094a', `${RP}/callback-unattested`, `${RP}/callback?state=a-state&response_code=abc123`]
    ])('refuses the live URI when %s has replaced the attested entry', (_name, attested, live) => {
      expect(isUriUnderAttestedPrefix(live, attested)).toBe(false);
    });
  });

  it('matches only at a segment boundary', () => {
    // The whole point: plain string-prefix matching would accept this, and the
    // unattested-URI faults would stop discriminating.
    expect(isUriUnderAttestedPrefix(`${RP}/auth/request-unattested`, `${RP}/auth/request`)).toBe(false);
    expect(isUriUnderAttestedPrefix(`${RP}/auth/requests`, `${RP}/auth/request`)).toBe(false);
    expect(isUriUnderAttestedPrefix(`${RP}/auth/request/sub/deeper`, `${RP}/auth/request`)).toBe(true);
  });

  it('accepts an exact match', () => {
    expect(isUriUnderAttestedPrefix(`${RP}/auth/response`, `${RP}/auth/response`)).toBe(true);
  });

  it('ignores trailing slashes on either side', () => {
    expect(isUriUnderAttestedPrefix(`${RP}/auth/request/`, `${RP}/auth/request`)).toBe(true);
    expect(isUriUnderAttestedPrefix(`${RP}/auth/request`, `${RP}/auth/request/`)).toBe(true);
  });

  it('ignores the query and fragment, which is where per-session data lives', () => {
    expect(isUriUnderAttestedPrefix(`${RP}/callback?response_code=abc#frag`, `${RP}/callback`)).toBe(true);
  });

  it('requires the same origin', () => {
    expect(isUriUnderAttestedPrefix('https://attacker.example.org/callback', `${RP}/callback`)).toBe(false);
    // Scheme and port are part of the origin.
    expect(isUriUnderAttestedPrefix('http://rp.example.org/callback', `${RP}/callback`)).toBe(false);
    expect(isUriUnderAttestedPrefix('https://rp.example.org:8443/callback', `${RP}/callback`)).toBe(false);
  });

  it('refuses a shorter path than the attested one', () => {
    expect(isUriUnderAttestedPrefix(`${RP}/auth`, `${RP}/auth/request`)).toBe(false);
  });

  it('refuses rather than throws when either side is not a URL', () => {
    expect(isUriUnderAttestedPrefix('/auth/request/a-state', `${RP}/auth/request`)).toBe(false);
    expect(isUriUnderAttestedPrefix(`${RP}/auth/request/a-state`, 'not a url')).toBe(false);
  });
});
