import { isTestCategory, readPackageVersion, testCategoryNames, type TestCategory } from '@itw-conformance-tool/utils';
import { Argument, Command, InvalidArgumentError } from 'commander';

import { init, type InitFlags } from './commands/init.js';
import { reportCreate } from './commands/reportCreate.js';
import { reportList } from './commands/reportList.js';
import { runConformanceTests } from './commands/runTests.js';

export function createProgram(): Command {
  const program = new Command()
    .name('itwct')
    .description('Local CLI for IT Wallet Conformance flows')
    .showHelpAfterError();

  program
    .command('init')
    .description('Initialize local workspace assets (data directory and config.ini template)')
    .option('-f, --force', 'overwrite init-generated files')
    .action(async (options: { force?: boolean }) => {
      const flags: InitFlags = { force: options.force ?? false };
      await init(flags);
    });

  program
    .command('test')
    .description('Run all conformance tests or a selected category')
    .addArgument(new Argument('[category]', `one of: ${testCategoryNames.join(', ')}`).argParser(parseTestCategory))
    .action(async (category: TestCategory | undefined) => {
      await runConformanceTests(category);
    });

  const report = program.command('report').description('Manage conformance test reports');

  report
    .command('list')
    .alias('ls')
    .description('List all conformance test runs')
    .action(() => {
      reportList();
    });

  report
    .command('create <run_id|latest> <format>')
    .description('Generate an HTML or PDF conformance report for a run ID or the latest run')
    .option('--view <view>', 'Which view to render: both (default), executive, or technical', 'both')
    .action(async (runId, format, options) => {
      await reportCreate(runId, format, options.view);
    });

  program.version(readPackageVersion(), '-v, --version', 'display the CLI version');

  return program;
}

function parseTestCategory(value: string): TestCategory {
  const category = value.toLowerCase();
  if (!isTestCategory(category)) {
    throw new InvalidArgumentError(
      `Invalid test category: ${value}. Allowed categories are: ${testCategoryNames.join(', ')}`
    );
  }

  return category;
}
