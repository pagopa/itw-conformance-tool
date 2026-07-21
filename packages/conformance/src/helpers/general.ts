export const isHttpsUrl = (value: unknown, allowQuery = true): boolean => {
  if (typeof value !== 'string') {
    return false;
  }

  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      url.hostname.length > 0 &&
      url.hash.length === 0 &&
      (allowQuery || url.search.length === 0)
    );
  } catch {
    return false;
  }
};

export const isObject = (value: unknown): boolean => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};

export const trimTrailingSlash = (url: string): string => {
  return url.endsWith('/') ? url.slice(0, -1) : url;
};
