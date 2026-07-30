import QRCode from 'qrcode';

import { CREDENTIAL_OFFER_QUERY_PARAM, CREDENTIAL_OFFER_URI_SCHEME } from '../domain/credential-offer.js';

import type { FastifyPluginAsync } from 'fastify';

const SCENARIO_CREDENTIAL_OFFER_QUERY_PARAM = 'credential_offer_uri';

const HTML_ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
};

/** Escapes text for safe interpolation into HTML element content/attributes. */
function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => HTML_ESCAPE_MAP[char] as string);
}

/**
 * Serializes a string as a JS string literal safe to inline in a `<script>`
 * element: escapes quotes/backslashes via `JSON.stringify` and additionally
 * neutralizes `<`, `>`, and `&` so the literal cannot prematurely close the
 * surrounding `<script>` tag or be misinterpreted as HTML.
 */
function toInlineScriptStringLiteral(value: string): string {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isValidCredentialOfferUri(uri: string): boolean {
  let parsed: URL;

  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  if (`${parsed.protocol}//` !== CREDENTIAL_OFFER_URI_SCHEME) return false;

  const credentialOffer = parsed.searchParams.get(CREDENTIAL_OFFER_QUERY_PARAM);
  if (!credentialOffer) return false;

  try {
    return isRecord(JSON.parse(credentialOffer));
  } catch {
    return false;
  }
}

async function renderCredentialOfferPage(uri: string): Promise<string> {
  const qrSvg = await QRCode.toString(uri, { type: 'svg' });
  const escapedUri = escapeHtml(uri);
  const inlineUri = toInlineScriptStringLiteral(uri);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Credential Offer</title>
<style>
  body {
    font-family: system-ui, -apple-system, sans-serif;
    max-width: 480px;
    margin: 3rem auto;
    padding: 0 1rem;
    text-align: center;
    color: #1a1a1a;
  }
  h1 { font-size: 1.4rem; }
  p { color: #444; }
  .qr { margin: 1.5rem auto; width: 260px; }
  .qr svg { width: 100%; height: 100%; }
  textarea {
    width: 100%;
    box-sizing: border-box;
    font-family: ui-monospace, monospace;
    font-size: 0.75rem;
    padding: 0.5rem;
    resize: vertical;
  }
  button {
    margin-top: 0.75rem;
    padding: 0.5rem 1.25rem;
    font-size: 1rem;
    cursor: pointer;
  }
  #copy-status { min-height: 1.25rem; font-size: 0.9rem; }
</style>
</head>
<body>
<h1>Credential Offer</h1>
<p>Scan this QR code with a Wallet Instance, or copy the URI below.</p>
<div class="qr">${qrSvg}</div>
<textarea id="offer-uri" rows="4" readonly>${escapedUri}</textarea>
<button id="copy-button" type="button">Copy URI</button>
<p id="copy-status" role="status"></p>
<script>
(function () {
  var uri = ${inlineUri};
  var button = document.getElementById('copy-button');
  var status = document.getElementById('copy-status');
  var textarea = document.getElementById('offer-uri');

  function showStatus(message, isError) {
    status.textContent = message;
    status.style.color = isError ? '#b00020' : '#0a7d2c';
  }

  function fallbackCopy() {
    try {
      textarea.focus();
      textarea.select();
      var successful = document.execCommand('copy');
      showStatus(successful ? 'Copied to clipboard!' : 'Copy failed. Select the text manually.', !successful);
    } catch (err) {
      showStatus('Copy failed. Select the text manually.', true);
    }
  }

  button.addEventListener('click', function () {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(uri).then(
        function () { showStatus('Copied to clipboard!', false); },
        fallbackCopy
      );
    } else {
      fallbackCopy();
    }
  });
})();
</script>
</body>
</html>
`;
}

const credentialOfferRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/credential-offer',
    method: 'GET',
    schema: {
      querystring: {
        type: 'object',
        properties: {
          [SCENARIO_CREDENTIAL_OFFER_QUERY_PARAM]: { type: 'string' }
        },
        additionalProperties: false
      },
      tags: ['Credential Offer']
    },
    handler: async (request, reply) => {
      const query = request.query as { [SCENARIO_CREDENTIAL_OFFER_QUERY_PARAM]?: unknown };
      const scenarioCredentialOfferUri = query[SCENARIO_CREDENTIAL_OFFER_QUERY_PARAM];
      if (scenarioCredentialOfferUri !== undefined && typeof scenarioCredentialOfferUri !== 'string') {
        reply.code(400);
        return { message: 'Invalid credential_offer_uri query parameter' };
      }

      const uri = scenarioCredentialOfferUri ?? app.config.CREDENTIAL_OFFER_URI;
      if (uri === undefined) {
        reply.code(404);
        return { message: 'Not Found' };
      }

      if (!isValidCredentialOfferUri(uri)) {
        reply.code(400);
        return { message: 'Invalid credential_offer_uri query parameter' };
      }

      const html = await renderCredentialOfferPage(uri);
      reply.type('text/html; charset=utf-8');
      return reply.send(html);
    }
  });
};

export default credentialOfferRoute;
