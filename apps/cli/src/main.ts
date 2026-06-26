import { createLogger } from '@itw-conformance-tool/logger';

import { init } from './commands/init.js';
import { reportCreate } from './commands/reportCreate.js';
import { reportList } from './commands/reportList.js';
import { test } from './commands/test.js';
import { buildEnv } from './services/buildEnv.js';
import { getNxCommands } from './services/getNxCommands.js';
import { loadConfigs } from './services/loadConfigs.js';
import { parseCLIArgs } from './services/parseCLIArgs.js';
import { runCommands } from './services/runCommands.js';
import { createEmitter } from './utils/prompt.js';
import { findNxRoot, existsFileSync, filesToSearch } from './utils/search.js';

async function main(): Promise<void> {
  console.clear();
  process.stdout.write('\x1Bc');

  const starterLogger = createLogger({ level: 'trace' });
  let emitLog = createEmitter(starterLogger);

  try {
    const nxRootPath = findNxRoot();
    const { command, flags } = parseCLIArgs(process.argv.slice(2), nxRootPath);

    // __ Init section
    if (command === 'init') {
      await init(flags);
      process.stdout.write('\nStart services with:\n  itw-conformance-tool start --all\n');
      process.exit(0);
    }

    const configs = loadConfigs(flags);

    // Change logger because log level might have been updated in the config file
    const paramLogger = createLogger({ level: configs.global.log_level });
    emitLog = createEmitter(paramLogger);

    // __ Report list section
    if (command === 'report:list') {
      reportList(configs.global.data_dir, emitLog);
      process.exit(0);
    }

    // __ Report create section
    if (command === 'report:create') {
      if (!flags.runId) {
        throw new Error('Missing required param: <uuid>');
      }
      await reportCreate(flags.runId, flags.format, configs.global.data_dir, emitLog);
      process.exit(0);
    }

    const missingFiles = filesToSearch(configs.global.data_dir, configs.global.https).filter((f) => !existsFileSync(f));
    if (missingFiles.length > 0) {
      throw new Error(
        'Missing required files:\n' + missingFiles.join('\n') + '\n\nRun first: `itw-conformance-tool init`\n'
      );
    }

    const services = getNxCommands(flags);
    const env = buildEnv(configs, emitLog);

    // __ Test section
    if (command.startsWith('test')) {
      await test(flags, env, emitLog);
      process.exit(0);
    }

    // __ Start section
    const exitCode = await runCommands(nxRootPath, services, env, emitLog);

    if (exitCode === 0) process.exit(0);
    throw new Error(`Nx CLI process exited with code ${exitCode}`);
  } catch (error) {
    if (error instanceof Error) {
      emitLog(error.stack ?? `${error.name}: ${error.message}`, 'error');
    } else {
      emitLog(`Unknown error: ${String(error)}`, 'error');
    }

    process.exit(1);
  }
}

await main();
