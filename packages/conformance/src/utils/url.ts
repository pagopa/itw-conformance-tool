export function normalizeUrl(url: string): string {
  let normalized = url;
  while (normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

export function isHttpsUrl(value: unknown): boolean {
  if (typeof value !== 'string') return false;

  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}
