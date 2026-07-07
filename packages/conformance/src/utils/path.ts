import { homedir } from 'node:os';
import { resolve } from 'node:path';

/** Utility function to resolve a file path, expanding the tilde (~)
 * to the user's home directory and resolving relative paths.
 *
 * @param path - The path to resolve.
 * @returns The resolved path.
 */
export function expandPath(inputPath: string): string {
  const path = inputPath.trim().replace(/^['"`]+|['"`]+$/g, '');

  if (path === '~') {
    return homedir();
  }

  if (path.startsWith('~/')) {
    return resolve(homedir(), path.slice(2));
  }

  return resolve(path);
}
