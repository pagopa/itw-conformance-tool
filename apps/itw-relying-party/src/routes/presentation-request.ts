import { escapeHtml, toInlineScriptStringLiteral } from '@itw-conformance-tool/utils';
import QRCode from 'qrcode';

import type { FastifyPluginAsync } from 'fastify';

const ENGAGEMENT_URI_QUERY_PARAM = 'uri';

/** Query parameters every presentation engagement URI carries, whatever
 * wallet scheme or universal link it is built on. */
const REQUIRED_ENGAGEMENT_PARAMS = ['client_id', 'request_uri'] as const;

/** Validates that a URI is a presentation engagement built by this Relying Party.
 *
 * The wallet launch base is configurable, so the scheme and host are not
 * constrained; what identifies the engagement is the OpenID4VP parameter set.
 *
 * @param uri - The candidate engagement URI.
 * @returns Whether the URI can be rendered as a presentation engagement.
 */
export function isValidEngagementUri(uri: string): boolean {
  let parsed: URL;

  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  return REQUIRED_ENGAGEMENT_PARAMS.every((param) => {
    const value = parsed.searchParams.get(param);

    return value !== null && value.length > 0;
  });
}

/** Renders the scan page for a presentation engagement URI.
 *
 * The QR code is generated server-side as an SVG so the page needs no external
 * script or font, matching the Credential Offer page and the Relying Party's
 * content security policy.
 *
 * @param uri - The engagement URI to encode.
 * @returns The complete HTML document.
 */
export async function renderPresentationRequestPage(uri: string): Promise<string> {
  const qrSvg = await QRCode.toString(uri, { type: 'svg' });
  const escapedUri = escapeHtml(uri);
  const inlineUri = toInlineScriptStringLiteral(uri);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Presentation Request</title>
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
<h1>Presentation Request</h1>
<p>Scan this QR code with the Wallet Instance under test, or copy the URI below.</p>
<div class="qr">${qrSvg}</div>
<textarea id="engagement-uri" rows="4" readonly>${escapedUri}</textarea>
<button id="copy-button" type="button">Copy URI</button>
<p id="copy-status" role="status"></p>
<script>
(function () {
  var uri = ${inlineUri};
  var button = document.getElementById('copy-button');
  var status = document.getElementById('copy-status');
  var textarea = document.getElementById('engagement-uri');

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

const presentationRequestRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/presentation-request',
    method: 'GET',
    schema: {
      summary: 'Render a scannable presentation engagement',
      description:
        'Shows the engagement URI of an interactive presentation scenario as a QR code for cross-device flows.',
      querystring: {
        type: 'object',
        properties: {
          [ENGAGEMENT_URI_QUERY_PARAM]: { type: 'string' }
        },
        required: [ENGAGEMENT_URI_QUERY_PARAM],
        additionalProperties: false
      },
      tags: ['Authorization']
    },
    handler: async (request, reply) => {
      const query = request.query as { [ENGAGEMENT_URI_QUERY_PARAM]?: unknown };
      const uri = query[ENGAGEMENT_URI_QUERY_PARAM];

      if (typeof uri !== 'string' || !isValidEngagementUri(uri)) {
        reply.code(400);

        return { message: 'Invalid uri query parameter' };
      }

      const html = await renderPresentationRequestPage(uri);
      reply.type('text/html; charset=utf-8');

      return reply.send(html);
    }
  });
};

export default presentationRequestRoute;
