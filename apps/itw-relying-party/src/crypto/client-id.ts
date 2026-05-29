/** Extracts the `client_id` from the RP's base URL
 *
 * @param baseUrl - The base URL of the RP, which may include a trailing slash
 * @returns The `client_id` derived from the base URL, with any trailing slashes removed
 */
export function extractClientId(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '');
}
