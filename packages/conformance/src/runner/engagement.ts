import QRCode from 'qrcode';

/** Hosts a wallet running on a separate device cannot reach: they resolve to
 * the wallet's own device, not to the machine running the local services. */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

/** Renders an engagement URI as a QR code drawn with terminal half-blocks.
 *
 * The code carries its own light background, so it stays scannable in a dark
 * terminal.
 *
 * @param payload - The engagement URI to encode.
 * @returns The rendered QR code, or `undefined` when the payload exceeds what a QR code can carry.
 */
export async function renderTerminalQrCode(payload: string): Promise<string | undefined> {
  try {
    return await QRCode.toString(payload, { type: 'terminal', small: true });
  } catch {
    return undefined;
  }
}

/** Builds the URL of the Relying Party page that shows an engagement as a QR code.
 *
 * @param relyingParty - The local Relying Party base URL.
 * @param engagementUri - The engagement URI to render.
 * @returns The absolute page URL.
 */
export function createPresentationRequestPageUrl(relyingParty: string, engagementUri: string): string {
  const pageUrl = new URL('/presentation-request', relyingParty);
  pageUrl.searchParams.set('uri', engagementUri);

  return pageUrl.toString();
}

/** Reports whether an engagement points at a host only reachable from the
 * machine running the services.
 *
 * A cross-device QR flow against such a host always times out: the wallet
 * resolves the host on its own device.
 *
 * @param engagementUri - The engagement URI shown to the tester.
 * @returns Whether the `request_uri` the wallet must fetch targets a loopback host.
 */
export function targetsLoopbackHost(engagementUri: string): boolean {
  let requestUri: string | null;

  try {
    requestUri = new URL(engagementUri).searchParams.get('request_uri');
  } catch {
    return false;
  }

  if (!requestUri) return false;

  try {
    return LOOPBACK_HOSTS.has(new URL(requestUri).hostname);
  } catch {
    return false;
  }
}
