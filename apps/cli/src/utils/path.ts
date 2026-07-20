import { homedir } from 'node:os';
import { join, isAbsolute, resolve } from 'node:path';

/** Utility function to resolve a file path, expanding the tilde (~)
 * to the user's home directory and resolving relative paths.
 *
 * @param path - The path to resolve.
 * @returns The resolved path.
 */
export function expandPath(path: string): string {
  path = path.replace(/"'`+/g, '').trim();

  if (path === '~') {
    return homedir();
  }

  if (path.startsWith('~/')) {
    return resolve(homedir(), path.slice(2));
  }

  if (!isAbsolute(path)) {
    return resolve(process.cwd(), path);
  }

  return join(path);
}
