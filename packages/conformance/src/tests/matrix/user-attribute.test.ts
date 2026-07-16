import * as fs from 'node:fs';

import { beforeAll, describe, expect, it } from 'vitest';

function resolveRpBaseUrl(): string {
  const fromEnv = process.env.ITW_CT_RP_BASE_URL?.trim();
  if (fromEnv) {
    let normalized = fromEnv;
    while (normalized.endsWith('/')) {
      normalized = normalized.slice(0, -1);
    }
    return normalized;
  }

  const port = process.env.ITW_CT_RP_PORT?.trim() || '8080';
  const httpsRaw = process.env.ITW_CT_HTTPS?.trim().toLowerCase();
  const httpsEnabled = httpsRaw !== undefined ? httpsRaw === 'true' || httpsRaw === '1' : true;
  const protocol = httpsEnabled ? 'https' : 'http';
  return `${protocol}://127.0.0.1:${port}`;
}

function decodeJwtPayload<T>(jwt: string): T {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const payload = Buffer.from(parts[1]!, 'base64url').toString('utf8');
  return JSON.parse(payload) as T;
}

function requireSearchParam(url: URL, name: string): string {
  const value = url.searchParams.get(name);
  if (!value) {
    throw new Error(`Missing ${name} query parameter`);
  }
  return value;
}

async function readBodyText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return '<unreadable body>';
  }
}

type RequestObjectResponse = {
  url: string;
};

describe('RP attribute deletion conformance matrix', () => {
  const rpBaseUrl = resolveRpBaseUrl();

  beforeAll(() => {
    // NODE_EXTRA_CA_CERTS is read at Node.js startup.
    // Validate path and require callers to set NODE_EXTRA_CA_CERTS before starting tests.
    const caCertPath = process.env.ITW_CT_CA_CERT_PATH?.trim();
    if (!caCertPath) {
      return;
    }

    if (!fs.existsSync(caCertPath)) {
      throw new Error(`ITW_CT_CA_CERT_PATH does not exist: ${caCertPath}`);
    }

    if (process.env.NODE_EXTRA_CA_CERTS !== caCertPath) {
      throw new Error(
        `To trust the private CA, start Node with NODE_EXTRA_CA_CERTS=${caCertPath} (current: ${process.env.NODE_EXTRA_CA_CERTS ?? '<unset>'}). ` +
          'Changing NODE_EXTRA_CA_CERTS at runtime has no effect.'
      );
    }
  });

  it('WP_116: federation metadata exposes a valid RP erasure endpoint', async () => {
    const response = await fetch(`${rpBaseUrl}/.well-known/openid-federation`);
    const body = await readBodyText(response);

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/entity-statement+jwt');

    const metadataJwt = body;
    const payload = decodeJwtPayload<Record<string, unknown>>(metadataJwt);
    const metadata = payload['metadata'] as Record<string, unknown> | undefined;
    const verifier = metadata?.['openid_credential_verifier'] as Record<string, unknown> | undefined;
    const erasureEndpoint = verifier?.['erasure_endpoint'];

    expect(typeof erasureEndpoint).toBe('string');
    const erasureUrl = new URL(String(erasureEndpoint));
    expect(erasureUrl.pathname).toBe('/auth/erasure');

    if (process.env.ITW_CT_RP_BASE_URL?.trim()) {
      const configuredBaseUrl = new URL(rpBaseUrl);
      expect(erasureUrl.origin).toBe(configuredBaseUrl.origin);
    }
  });

  it('WP_117: wallet sends a valid deletion request to RP erasure endpoint', async () => {
    const requestObjectResponse = await fetch(`${rpBaseUrl}/request-object`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        dcqlQuery: {
          credentials: [{ id: 'pid', format: 'dc+sd-jwt' }]
        },
        flow_type: 'cross-device'
      })
    });

    const requestObjectBody = (await requestObjectResponse.json()) as RequestObjectResponse;
    expect(requestObjectResponse.status).toBe(200);

    const state = requireSearchParam(new URL(requestObjectBody.url), 'state');
    const callbackUrl = 'https://wallet.example.org/erasure-callback';

    const erasureResponse = await fetch(
      `${rpBaseUrl}/auth/erasure?state=${encodeURIComponent(state)}&callback_url=${encodeURIComponent(callbackUrl)}&attributes=family_name,given_name&attributes=birth_date`
    );

    const erasureBody = await readBodyText(erasureResponse);
    expect(erasureResponse.status, erasureBody).toBe(204);
    expect(erasureBody).toBe('');
  });

  it('WP_117: RP rejects deletion request with invalid state', async () => {
    const callbackUrl = 'https://wallet.example.org/erasure-callback';
    const erasureResponse = await fetch(
      `${rpBaseUrl}/auth/erasure?state=${encodeURIComponent('not-a-valid-uuid')}&callback_url=${encodeURIComponent(callbackUrl)}`
    );

    const erasureBody = (await erasureResponse.json()) as {
      error: string;
      error_description: string;
    };

    expect(erasureResponse.status).toBe(400);
    expect(erasureBody.error).toBe('bad_request');
    expect(erasureBody.error_description.length).toBeGreaterThan(0);
  });

  it('WP_118: wallet receives successful callback outcome after RP erasure redirect flow', async () => {
    const requestObjectResponse = await fetch(`${rpBaseUrl}/request-object`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        dcqlQuery: {
          credentials: [{ id: 'pid', format: 'dc+sd-jwt' }]
        },
        flow_type: 'cross-device'
      })
    });

    const requestObjectBody = (await requestObjectResponse.json()) as RequestObjectResponse;
    expect(requestObjectResponse.status).toBe(200);

    const state = requireSearchParam(new URL(requestObjectBody.url), 'state');
    const callbackUrl = 'https://wallet.example.org/after-erasure';

    const erasureResponse = await fetch(
      `${rpBaseUrl}/auth/erasure?state=${encodeURIComponent(state)}&callback_url=${encodeURIComponent(callbackUrl)}`
    );
    expect(erasureResponse.status).toBe(204);

    const statusResponse = await fetch(`${rpBaseUrl}/status/${encodeURIComponent(state)}`);
    const statusBody = (await statusResponse.json()) as { redirect_uri: string };

    expect(statusResponse.status).toBe(200);
    expect(statusBody.redirect_uri).toBe(`${callbackUrl}?response_code=success`);
  });
});
