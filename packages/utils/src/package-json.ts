import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

interface PackageJson {
  version: string;
}

/**
 * Resolves the repository root package manifest by walking upward from the
 * supplied directory until it finds the pnpm workspace marker.
 */
export function resolveRootPackageJsonPath(startDirectory = process.cwd()): string {
  let directory = resolve(startDirectory);

  while (!existsSync(join(directory, 'pnpm-workspace.yaml'))) {
    const parentDirectory = dirname(directory);
    if (parentDirectory === directory) {
      throw new Error(`Unable to resolve the repository root from "${startDirectory}".`);
    }
    directory = parentDirectory;
  }

  return join(directory, 'package.json');
}

/** Reads the version declared in the repository root package manifest. */
export function readPackageVersion(startDirectory = process.cwd()): string {
  const packageJson = JSON.parse(readFileSync(resolveRootPackageJsonPath(startDirectory), 'utf8')) as PackageJson;
  return packageJson.version;
}
