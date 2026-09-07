/**
 * Removes any trailing slashes from a string so equivalent URLs and
 * identifiers (e.g. federation entity IDs) compare cleanly.
 */
export function trimTrailingSlashes(value: string): string {
  let result = value;
  while (result.endsWith('/')) {
    result = result.slice(0, -1);
  }
  return result;
}

/**
 * Normalizes a URL for matching by trimming whitespace, dropping fragments,
 * and removing trailing slashes. Falls back to trimming the raw string if it
 * is not a valid URL.
 */
export function normalizeUrl(value: string): string {
  const trimmed = value.trim();

  try {
    const url = new URL(trimmed);
    url.hash = '';
    return trimTrailingSlashes(url.toString());
  } catch {
    return trimTrailingSlashes(trimmed);
  }
}

/**
 * Decides whether a live URI is covered by an attested one.
 *
 * A federation entity attests endpoint *bases* — `request_uris`,
 * `response_uris`, `redirect_uris` — while the URIs actually handed to a wallet
 * extend them with per-session data. So the comparison is a prefix one: same
 * origin, and a path that either equals the attested path or continues it at a
 * **segment boundary**. Query and fragment are ignored, since that is where the
 * per-session data usually lives.
 *
 * The segment boundary is what makes this safe. Plain string-prefix matching
 * would let an attested `/auth/request` accept `/auth/request-unattested`,
 * which is exactly the distinction the WP_081, WP_091a and WP_094a faults rest
 * on.
 *
 * @param liveUri - The URI a wallet was actually handed.
 * @param attestedUri - An entry from an attested endpoint list.
 * @returns Whether a wallet applying this rule accepts `liveUri`.
 */
export function isUriUnderAttestedPrefix(liveUri: string, attestedUri: string): boolean {
  let live: URL;
  let attested: URL;

  try {
    live = new URL(liveUri.trim());
    attested = new URL(attestedUri.trim());
  } catch {
    return false;
  }

  if (live.origin !== attested.origin) return false;

  const livePath = trimTrailingSlashes(live.pathname);
  const attestedPath = trimTrailingSlashes(attested.pathname);

  return livePath === attestedPath || livePath.startsWith(`${attestedPath}/`);
}
