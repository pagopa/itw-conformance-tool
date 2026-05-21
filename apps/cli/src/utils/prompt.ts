import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { type Logger, type Level } from '@itw-conformance-tool/logger';

/** Utility functions for the CLI, including logger creation and help printing.
 *
 * @param logger - A logger instance used for emitting structured log messages.
 * @returns A function that can be used to emit structured log messages with a
 * specified event name, details, and log level.
 */
export function createEmitter(logger: Logger): (event: string, type?: Level) => void {
  return (event, type = 'debug') => {
    logger[type](event);
  };
}

/** Print help information for the CLI, including usage, commands, options, and examples.
 *
 * @returns it outputs help information to the console.
 */
export function printHelp(): void {
  process.stdout.write(`\nitw-conformance-tool - Local CLI for ITW Conformance flows\n\n`);
  process.stdout.write('Usage:\n');
  process.stdout.write(`  itw-conformance-tool <command> [options]\n\n`);
  process.stdout.write('Commands:\n');
  process.stdout.write('  init           Initialize local workspace assets (data directory + config.ini template)\n');
  process.stdout.write('  start          Start local services via Nx\n');
  process.stdout.write('  -v, --version                      Show version\n');
  process.stdout.write('  -h, --help                         Show help\n\n');
  process.stdout.write('Options:\n');
  process.stdout.write('  -c, --config <path>                Config path (for init output and runtime overrides)\n');
  process.stdout.write('  -a, --all                          Start issuer and relying party (default for start)\n');
  process.stdout.write('  --issuer                           Start only itw-credential-issuer\n');
  process.stdout.write('  --rp                               Start only itw-relying-party\n');
  process.stdout.write('  -f, --force                        Force overwrite for init-generated files\n');
  process.stdout.write('Examples:\n');
  process.stdout.write(`  itw-conformance-tool init  --force\n`);
  process.stdout.write(`  itw-conformance-tool start --all\n`);
  process.stdout.write(`  itw-conformance-tool start --issuer\n\n`);
}

/** Utility function to read the version of the itw-conformance-tool
 *
 * @param rootPath - The root directory of the project.
 * @returns It reads the version from the package.json file and emits it using the provided emitter function.
 */
export function printVersion(rootPath: string): void {
  let version = 'unknown';
  const packageJsonPath = join(rootPath, 'apps/cli/package.json');
  if (existsSync(packageJsonPath)) {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
    version = packageJson.version || 'unknown';
  }

  process.stdout.write(`itw-conformance-tool version: ${version}\n`);
}
