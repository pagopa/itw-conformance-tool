import { join, isAbsolute } from 'node:path';

/** Utility function to resolve a file path, expanding the tilde (~)
 * to the user's home directory and resolving relative paths.
 *
 * @param path - The path to resolve.
 * @returns The resolved path.
 */
export function expandPath(path: string): string {
  path = path.replace(/"'`+/g, '').trim();

  if (path.startsWith('~')) {
    path = path.replace('~', process.cwd());
  }

  if (!isAbsolute(path)) {
    return join(path);
  }

  return join(path);
}
