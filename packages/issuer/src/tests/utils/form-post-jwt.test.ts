import { describe, expect, it } from 'vitest';

import { getFormPostFromRedirectUriAndJwt } from '../../utils/form-post-jwt.js';

describe('getFormPostFromRedirectUriAndJwt', () => {
  it('rejects invalid URLs', () => {
    expect(() => getFormPostFromRedirectUriAndJwt('not-a-url', 'jwt')).toThrow('Invalid redirectUri');
  });

  it('rejects non-http(s) protocols', () => {
    expect(() => getFormPostFromRedirectUriAndJwt('javascript:alert(1)', 'jwt')).toThrow(
      'Invalid redirectUri protocol'
    );
  });

  it('escapes HTML attribute values for redirectUri and jwt', () => {
    const redirectUri = 'https://example.com/cb?state="x"&q=<tag>&s=\'a\'';
    const jwt = "jwt\"<bad>&'token'";

    const html = getFormPostFromRedirectUriAndJwt(redirectUri, jwt);

    expect(html).toContain('action="https://example.com/cb?state=&quot;x&quot;&amp;q=&lt;tag&gt;&amp;s=&#39;a&#39;"');
    expect(html).toContain('value="jwt&quot;&lt;bad&gt;&amp;&#39;token&#39;"');
  });
});
