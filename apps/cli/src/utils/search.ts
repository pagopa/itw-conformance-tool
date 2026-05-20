import { existsSync, statSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

/** Utility function to find the root directory of an
 * Nx workspace by searching for the presence of 'nx.json' file.
 *
 * @param startDir - The directory to start the search from. Defaults to the current working directory.
 * @returns The root directory of the Nx workspace if found.
 */
export function findRoot(startDir = process.cwd()): string {
  let dir = startDir;
  while (true) {
    if (existsSync(join(dir, 'nx.json'))) return dir;

    const parent = join(dir, '..');
    if (parent === dir) break;

    dir = parent;
  }

  throw new Error(
    'Could not find the root of the Nx workspace. Please ensure you are running this command within the root of an Nx workspace.'
  );
}

/** Utility function to locate the local Nx CLI binary within
 * the node_modules of the CLI app.
 *
 * @param rootPath - The root directory of the project.
 * @returns The path to the local Nx CLI binary if found.
 */
export function searchNx(rootPath: string): string {
  const candidatePaths = [
    join(rootPath, 'node_modules/nx/dist/bin/nx.js'),
    join(rootPath, 'apps/cli/node_modules/nx/dist/bin/nx.js'),
    join(rootPath, 'apps/cli/node_modules/nx/bin/nx.js')
  ];

  const nxCliPath = candidatePaths.find((candidatePath) => existsSync(candidatePath));

  if (nxCliPath) {
    return nxCliPath;
  }

  throw new Error(`Unable to locate the local Nx CLI in node_modules. Checked paths: ${candidatePaths.join(', ')}`);
}

/** Expands a file path that may contain a tilde (~) or be enclosed in quotes,
 * replacing the tilde with the provided root path.
 *
 * @param path - The path that may contain a tilde.
 * @param rootPath - The root path to replace the tilde with.
 * @returns The expanded path with ~ replaced by the root path.
 */
export function expandPath(path: string, rootPath: string): string {
  if ((path.startsWith('"') && path.endsWith('"')) || (path.startsWith("'") && path.endsWith("'"))) {
    path = path.slice(1, -1);
  }

  if (path.startsWith('~')) {
    path = path.replace('~', rootPath);
  }

  if (!isAbsolute(path)) {
    return join(rootPath, path);
  }

  return join(path);
}

/** Creates the file paths for the required keys and certificates
 * based on the provided root path.
 *
 * @param fileRootPath - The root path for the files.
 * @param rootPath - The root path to replace the tilde with.
 * @returns An array of file paths for the required keys and certificates.
 */
export function createFileDirPaths(filePath: string): string[] {
  return [
    join(filePath, 'issuer', 'signing-keys.jwks.json'),
    join(filePath, 'issuer', 'iaca-cert.pem'),
    join(filePath, 'issuer', 'iaca-key.pem'),
    join(filePath, 'rp', 'auth-request-key.jwk.json'),
    join(filePath, 'rp', 'auth-response-key.jwk.json')
  ];
}

/** Utility function to check if a given path exists and is a file.
 *
 * @param path - The path to check for existence and file type.
 * @returns A boolean indicating whether the path exists and is a file.
 */
export function existsFileSync(path: string): boolean {
  try {
    if (!existsSync(path)) {
      return false;
    }

    return statSync(path).isFile();
  } catch {
    return false;
  }
}
