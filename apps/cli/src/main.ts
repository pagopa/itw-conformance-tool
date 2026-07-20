import { resolve } from 'node:path';

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

    const loadedConfigs = loadConfigs(flags);
    const configs = loadedConfigs.data;

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

    if (!loadedConfigs.ok) {
      throw new Error(
        `${loadedConfigs.error}\n` +
          'The start/test commands require [global].wallet_provider_backend_url in config.ini.\n' +
          'Run `itw-conformance-tool init` and set wallet_provider_backend_url, then retry.'
      );
    }

    const runtimeConfigs = loadedConfigs.data;

    const missingFiles = filesToSearch(runtimeConfigs.global.data_dir, runtimeConfigs.global.https).filter(
      (f) => !existsFileSync(f)
    );
    if (missingFiles.length > 0) {
      throw new Error(
        'Missing required files:\n' + missingFiles.join('\n') + '\n\nRun first: `itw-conformance-tool init`\n'
      );
    }

    const services = getNxCommands(flags);
    const configFilePath = flags.config.value ? flags.config.path : resolve(process.cwd(), 'config.ini');
    const env = buildEnv(runtimeConfigs, emitLog, configFilePath);

    // __ Test section
    if (command === 'test') {
      await test(env, emitLog);
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
