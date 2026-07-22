import { loadConfig } from '@itw-conformance-tool/config';
import { reportCreate } from '@itw-conformance-tool/conformance';
import { createLogger } from '@itw-conformance-tool/logger';
import { Argument, Command, InvalidArgumentError } from 'commander';

import { init } from './commands/init.js';
import { runConformanceTests } from './commands/runTests.js';
import { isTestCategory, testCategories, type TestCategory } from './commands/testCategories.js';
import { getNxCommands } from './services/getNxCommands.js';
import { runCommands } from './services/runCommands.js';
import { createEmitter } from './utils/prompt.js';
import { existsFileSync, filesToSearch, findNxRoot } from './utils/search.js';

import type { InitFlags, StartFlags } from './types/types.js';

type StartOptions = {
  all?: boolean;
  issuer?: boolean;
  rp?: boolean;
  trustAnchor?: boolean;
};

function parseTestCategory(value: string): TestCategory {
  const category = value.toLowerCase();
  if (!isTestCategory(category)) {
    throw new InvalidArgumentError(
      `Invalid test category: ${value}. Allowed categories are: ${testCategories.join(', ')}`
    );
  }

  return category;
}

async function start(flags: StartFlags): Promise<void> {
  const nxRootPath = findNxRoot();
  const config = loadConfig();
  const emitLog = createEmitter(createLogger({ level: config.global.log_level }));
  const missingFiles = filesToSearch(config.global.data_dir).filter((file) => !existsFileSync(file));

  if (missingFiles.length > 0) {
    throw new Error(
      'Missing required files:\n' + missingFiles.join('\n') + '\n\nRun first: `itw-conformance-tool init`\n'
    );
  }

  process.exitCode = await runCommands(nxRootPath, getNxCommands(flags), emitLog);
}

async function test(category: TestCategory): Promise<void> {
  loadConfig();
  process.exitCode = await runConformanceTests(category);
}

async function listReports(): Promise<void> {
  throw new Error('Not implemented yet.');
}

function createProgram(): Command {
  const program = new Command().name('itwct').description('Local CLI for ITW Conformance flows').showHelpAfterError();

  program
    .command('init')
    .description('Initialize local workspace assets (data directory and config.ini template)')
    .option('-f, --force', 'overwrite init-generated files')
    .action(async (options: { force?: boolean }) => {
      const flags: InitFlags = { force: options.force ?? false };
      await init(flags);
    });

  program
    .command('start')
    .description('Start local services via Nx')
    .option('-a, --all', 'start the trust anchor, issuer, and relying party')
    .option('--issuer', 'start only itw-credential-issuer')
    .option('--rp', 'start only itw-relying-party')
    .option('--trust-anchor', 'start only itw-trust-anchor')
    .action(async (options: StartOptions) => {
      const flags: StartFlags = {
        all: options.all ?? false,
        issuer: options.issuer ?? false,
        rp: options.rp ?? false,
        trustAnchor: options.trustAnchor ?? false
      };
      await start(flags);
    });

  program
    .command('test')
    .description('Run a selected conformance test category')
    .addArgument(new Argument('<category>', `one of: ${testCategories.join(', ')}`).argParser(parseTestCategory))
    .action(async (category: TestCategory) => {
      await test(category);
    });

  program
    .command('report:list')
    .description('List all conformance runs stored in the database')
    .action(async () => {
      await listReports();
    });

  program
    .command('create <run_id|latest> <format>')
    .description('Generate an HTML or PDF conformance report for a run ID or the latest run')
    .option('--view <view>', 'Which view to render: both (default), executive, or technical', 'both')
    .action(async (runId, format, options) => {
      await reportCreate(runId, format, options.view);
    });

  program
    .command('version')
    .description('display the CLI version')
    .action(() => {
      process.stdout.write('0.1.0\n');
    });

  program.version('0.1.0', '-v, --version', 'display the CLI version');

  return program;
}

function normalizeArgv(argv: string[]): string[] {
  if (argv.length === 3) {
    const [node, executable, combinedArgs] = argv;
    return [node, executable, ...combinedArgs.split(/\s+/).filter(Boolean)];
  }

  return argv;
}

export async function run(argv = process.argv): Promise<void> {
  await createProgram().parseAsync(normalizeArgv(argv));
}
