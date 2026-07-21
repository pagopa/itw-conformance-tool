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
