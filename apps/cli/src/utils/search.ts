import { existsSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

/** Utility function to find the root directory of the Nx workspace
 * by looking for the presence of 'nx.json'.
 *
 * @param startDir - The directory to start the search from. Defaults to the current working directory.
 * @returns The root directory of the Nx workspace if found.
 */
export function findNxRoot(startDir = process.cwd()): string {
  let dir = startDir;
  while (true) {
    if (existsSync(resolve(dir, 'nx.json'))) return dir;

    const parent = resolve(dir, '..');
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

/** Utility function to create an array of file paths that need to be checked for existence,
 *
 * @param filePath - The base path for the files.
 * @param httpsEnabled - Whether HTTPS is enabled; when true, TLS cert/key paths are included.
 * @returns An array of file paths for the required keys and certificates.
 */
export function filesToSearch(filePath: string, httpsEnabled = false): string[] {
  const paths = [
    join(filePath, 'issuer', 'signing-keys.jwks.json'),
    join(filePath, 'issuer', 'iaca-cert.pem'),
    join(filePath, 'issuer', 'iaca-key.pem'),
    join(filePath, 'rp', 'auth-request-key.jwk.json'),
    join(filePath, 'rp', 'auth-response-key.jwk.json')
  ];

  if (httpsEnabled) {
    paths.push(join(filePath, 'tls-cert.pem'), join(filePath, 'tls-key.pem'));
  }

  return paths;
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
