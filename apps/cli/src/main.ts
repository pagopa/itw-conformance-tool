import { createLogger } from '@itw-conformance-tool/logger';

import { init } from './commands/init.js';
import { reportCreate } from './commands/reportCreate.js';
import { reportList } from './commands/reportList.js';
import { runConformanceTests } from './commands/runTests.js';
import { getNxCommands } from './services/getNxCommands.js';
import { loadConfig } from './services/loadConfig.js';
import { parseCliArgs } from './services/parseCliArgs.js';
import { runCommands } from './services/runCommands.js';
import { createEmitter } from './utils/prompt.js';
import { findNxRoot, existsFileSync, filesToSearch } from './utils/search.js';

async function main() {
  const nxRootPath = findNxRoot();
  const { command, flags } = parseCliArgs(process.argv.slice(2), nxRootPath);

  // __ Init section
  if (command === 'init') {
    await init(flags);
    process.stdout.write('Start services with: itwct start --all');
    process.exit(0);
  }

  const { data: config, configFilePath } = loadConfig(flags);
  const logLevel = config.global.log_level;
  const dataDir = config.global.data_dir;

  const starterLogger = createLogger({ level: logLevel });
  const emitLog = createEmitter(starterLogger);

  // __ Test section
  if (command === 'test') {
    await runConformanceTests();
    process.exit(0);
  }

  // __ Report list section
  if (command === 'report:list') {
    reportList(dataDir, emitLog);
    process.exit(0);
  }

  // __ Report create section
  if (command === 'report:create') {
    if (!flags.runId) {
      throw new Error('Missing required param: <uuid>');
    }
    await reportCreate(flags.runId, flags.format, dataDir, emitLog);
    process.exit(0);
  }

  const missingFiles = filesToSearch(dataDir).filter((f) => !existsFileSync(f));
  if (missingFiles.length > 0) {
    throw new Error(
      'Missing required files:\n' + missingFiles.join('\n') + '\n\nRun first: `itw-conformance-tool init`\n'
    );
  }

  const services = getNxCommands(flags, configFilePath);

  // __ Start section
  const exitCode = await runCommands(nxRootPath, services, emitLog);

  process.exit(exitCode);
}

await main();
