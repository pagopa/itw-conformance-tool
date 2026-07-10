import { createLogger } from '@itw-conformance-tool/logger';

import { init } from './commands/init.js';
import { reportCreate } from './commands/reportCreate.js';
import { reportList } from './commands/reportList.js';
import { runConformanceTests } from './commands/runTests.js';
import { buildEnv } from './services/buildEnv.js';
import { getNxCommands } from './services/getNxCommands.js';
import { loadConfig } from './services/loadConfigs.js';
import { parseCLIArgs } from './services/parseCLIArgs.js';
import { runCommands } from './services/runCommands.js';
import { createEmitter } from './utils/prompt.js';
import { findNxRoot, existsFileSync, filesToSearch } from './utils/search.js';

async function main() {
  const nxRootPath = findNxRoot();
  const { command, flags } = parseCLIArgs(process.argv.slice(2), nxRootPath);

  const configResult = loadConfig(flags);
  if (!configResult.ok) {
    throw new Error('Failed to load configuration: ' + configResult.error);
  }

  const config = configResult.data;

  const starterLogger = createLogger({ level: config.global.log_level });
  const emitLog = createEmitter(starterLogger);

  // __ Init section
  if (command === 'init') {
    await init(flags);
    process.stdout.write('\nStart services with:\n  itw-conformance-tool start --all\n');
    process.exit(0);
  }

  // __ Report list section
  if (command === 'report:list') {
    reportList(config.global.data_dir, emitLog);
    process.exit(0);
  }

  // __ Report create section
  if (command === 'report:create') {
    if (!flags.runId) {
      throw new Error('Missing required param: <uuid>');
    }
    await reportCreate(flags.runId, flags.format, config.global.data_dir, emitLog);
    process.exit(0);
  }

  const missingFiles = filesToSearch(config.global.data_dir).filter((f) => !existsFileSync(f));
  if (missingFiles.length > 0) {
    throw new Error(
      'Missing required files:\n' + missingFiles.join('\n') + '\n\nRun first: `itw-conformance-tool init`\n'
    );
  }

  const services = getNxCommands(flags);
  const env = buildEnv(config);

  // __ Test section
  if (command === 'test') {
    await runConformanceTests(env);
    process.exit(0);
  }

  // __ Start section
  const exitCode = await runCommands(nxRootPath, services, env, emitLog);

  process.exit(exitCode);
}

await main();
