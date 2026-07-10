import { existsSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { SearchParamResult } from '../types/types.js';

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
export function filesToSearch(filePath: string): string[] {
  const paths = [
    join(filePath, 'issuer', 'jwks.json'),
    join(filePath, 'issuer', 'iaca-cert.pem'),
    join(filePath, 'issuer', 'iaca-key.pem'),
    join(filePath, 'rp', 'auth-request-key.jwk.json'),
    join(filePath, 'rp', 'auth-response-key.jwk.json'),
    join(filePath, 'rp', 'federation-key.jwk.json'),
    join(filePath, 'rp', 'x5c-cert.pem')
  ];

  return paths;
}

/** Utility function to check if a given path exists and is a file.
 *
 * @param filePath - The path to check for existence and file type.
 * @returns A boolean indicating whether the path exists and is a file.
 */
export function existsFileSync(filePath: string): boolean {
  try {
    if (!existsSync(filePath)) {
      return false;
    }

    return statSync(filePath).isFile();
  } catch {
    return false;
  }
}

/** Utility function to remove surrounding quotes from a
 * string value.
 *
 * @param value - The string value to unquote.
 * @returns The unquoted string value.
 */
function unquote(value: string): string {
  return value.replace(/^['"]+|['"]+$/g, '');
}

/** Utility function to search for a parameter value in an array
 * of command-line arguments, handling both inline and separate values.
 *
 * @param param - The parameter name to search for (e.g., '--config' or '-c').
 * @param args - The array of command-line arguments to search through.
 * @returns An object containing the found value and the remaining arguments,
 * or null if not found.
 */
export function searchParamValue(param: string, args: string[]): SearchParamResult | null {
  const inlineIndex = args.findIndex((arg) => arg.startsWith(`${param}=`));

  if (inlineIndex !== -1) {
    return {
      value: unquote(args[inlineIndex].slice(param.length + 1)),
      remainingArgs: args.filter((_, i) => i !== inlineIndex)
    };
  }

  const index = args.indexOf(param);

  if (index !== -1 && index < args.length - 1) {
    return {
      value: unquote(args[index + 1]),
      remainingArgs: args.filter((_, i) => i !== index && i !== index + 1)
    };
  }

  return null;
}
