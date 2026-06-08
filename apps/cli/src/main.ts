import { createLogger } from '@itw-conformance-tool/logger';

import { buildEnv } from './services/buildEnv.js';
import { getNxCommands } from './services/getNxCommands.js';
import { init } from './services/init.js';
import { loadConfigs } from './services/loadConfigs.js';
import { parseCLIArgs } from './services/parseCLIArgs.js';
import { runCommands } from './services/runCommands.js';
import { createEmitter } from './utils/prompt.js';
import { findRoot, createFileDirPaths, existsFileSync } from './utils/search.js';

async function main(): Promise<void> {
  const starterLogger = createLogger({ level: 'trace' });
  let emitLog = createEmitter(starterLogger);

  try {
    const rootPath = findRoot();
    const { command, flags } = parseCLIArgs(process.argv.slice(2), rootPath);

    // Handle configs
    const { configs, configFileExists } = loadConfigs(flags, rootPath, emitLog);

    // Handle 'init' command separately to set up configuration and necessary files
    if (command === 'init') {
      init(rootPath, flags, configs, emitLog);
      emitLog('Start services with: itw-conformance-tool start --all', 'info');
      process.exit(0);
    }

    if (command === 'start') {
      if (!configFileExists) {
        const missingConfigPath = flags.config?.path ?? 'config.ini';
        emitLog(
          `${missingConfigPath} not found. Starting with default values.\nRun \`itw-conformance-tool init\` to create the configuration file.`,
          'warn'
        );
      }

      const missingFiles = createFileDirPaths(configs.global.data_dir, configs.global.https).filter(
        (f) => !existsFileSync(f)
      );
      if (missingFiles.length > 0) {
        throw new Error(
          `Missing required files: \n${missingFiles.join('\n')}\nPlease run \`itw-conformance-tool init\` to create the necessary keys and certificates.`
        );
      }
    }

    const logger = createLogger({ level: configs.global.log_level });
    emitLog = createEmitter(logger);

    // Start the selected services with Nx CLI
    const services = getNxCommands(flags);
    const env = buildEnv(configs, emitLog);
    const exitCode = await runCommands(rootPath, services, env, emitLog);

    if (exitCode === 0) process.exit(0);
    throw new Error(`Nx CLI process exited with code ${exitCode}`);
  } catch (error) {
    if (error instanceof Error) {
      emitLog(`${error.name}: ${error.message} | ${error.stack}`, 'error');
    } else {
      emitLog(`Unknown error: ${String(error)}`, 'error');
    }

    process.exit(1);
  }
}

await main();
