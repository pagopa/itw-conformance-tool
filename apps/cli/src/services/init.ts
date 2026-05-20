import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { parseINI, type ConfigType } from '@itw-conformance-tool/config';
import { type Level } from '@itw-conformance-tool/logger';

import { configINITemplate } from '../templates/templates.js';
import { getAuthRequestKey, getAuthResponseKey, getIACAChain, getSigningKeys } from '../utils/crypto.js';
import { existsFileSync, expandPath } from '../utils/search.js';

import type { CLIFlags } from '../types/types.js';

/** Initializes the configuration and necessary files for the CLI tool.
 * It creates the required directory structure and files based on the
 * provided flags. If the --force flag is used, it will overwrite
 * existing files and directories without prompting.
 *
 * @param flags - The command-line flags.
 * @param configs - The current configuration object.
 * @param configFileExists - A boolean indicating whether the configuration file already exists.
 * @param emitter - A function used to emit structured log messages.
 * @returns It performs file system operations and exits the process upon completion.
 */
export function init(
  rootPath: string,
  flags: CLIFlags,
  configs: ConfigType,
  configFileExists: boolean,
  emitter: (event: string, type?: Level) => void
): void {
  emitter('CLI init started.');
  const reportMessages = [`- Force overwrite: ${flags.force ? 'yes' : 'no'}`];
  const defaultConfigPath =
    flags.config.value && existsFileSync(flags.config.path)
      ? expandPath(flags.config.path, rootPath)
      : join(rootPath, 'config.ini');

  let dataDirPath = join(rootPath, '.itw-conformance-tool');
  let issuerDirPath = join(dataDirPath, 'issuer');
  let rpDirPath = join(dataDirPath, 'rp');
  const configFilePath = defaultConfigPath;

  let signingKeysPath = join(issuerDirPath, 'signing-keys.jwks.json');
  let iacaCertPath = join(issuerDirPath, 'iaca-cert.pem');
  let iacaKeyPath = join(issuerDirPath, 'iaca-key.pem');
  let authRequestKeyPath = join(rpDirPath, 'auth-request-key.jwk.json');
  let authResponseKeyPath = join(rpDirPath, 'auth-response-key.jwk.json');

  if (configFileExists && !flags.force) {
    dataDirPath = expandPath(configs.global.data_dir, rootPath);
    issuerDirPath = join(dataDirPath, 'issuer');
    rpDirPath = join(dataDirPath, 'rp');

    signingKeysPath = join(issuerDirPath, 'signing-keys.jwks.json');
    iacaCertPath = join(issuerDirPath, 'iaca-cert.pem');
    iacaKeyPath = join(issuerDirPath, 'iaca-key.pem');
    authRequestKeyPath = join(rpDirPath, 'auth-request-key.jwk.json');
    authResponseKeyPath = join(rpDirPath, 'auth-response-key.jwk.json');
  }

  const dirsPaths = [
    { path: dataDirPath, name: 'Data directory' },
    { path: issuerDirPath, name: 'Issuer directory' },
    { path: rpDirPath, name: 'Relying Party directory' }
  ];
  for (const dir of dirsPaths) {
    mkdirSync(dir.path, { recursive: true });
    reportMessages.push(`- ${dir.name} at: ${dir.path}`);
  }

  // Create config file if it doesn't exist or if --force is used, then read the config values
  if (!configFileExists || flags.force) {
    const configExisted = existsFileSync(configFilePath);
    writeFileSync(configFilePath, configINITemplate, { encoding: 'utf8', flag: 'w' });
    configs = parseINI(configFilePath).data;
    reportMessages.push(
      `- Config file ${configExisted ? 'overwritten' : 'created'} at: ${configFilePath}\n` +
        '  Content:\n' +
        JSON.stringify(configs, null, 2)
    );
  }

  const filesPaths = [
    { path: signingKeysPath, content: getSigningKeys(), name: 'Signing keys file' },
    { path: authRequestKeyPath, content: getAuthRequestKey(), name: 'Auth request key file' },
    { path: authResponseKeyPath, content: getAuthResponseKey(), name: 'Auth response key file' }
  ];
  for (const file of filesPaths) {
    const fileExists = existsFileSync(file.path);
    const shouldWriteFile = flags.force || !fileExists;
    if (shouldWriteFile) {
      reportMessages.push(`- ${fileExists ? 'Overwriting' : 'Creating'} file at: ${file.path}`);
      writeFileSync(file.path, file.content, { encoding: 'utf8', flag: 'w' });
    } else {
      reportMessages.push(`- ${file.name} already exists at: ${file.path} (skipped, use --force to regenerate)`);
    }
  }

  /* IACA cert and key should always be generated and overwritten together if
   * --force is used, as they are unique for each instance */
  const iacaCertExists = existsFileSync(iacaCertPath);
  const iacaKeyExists = existsFileSync(iacaKeyPath);
  const shouldWriteIaca = flags.force || !(iacaCertExists && iacaKeyExists);

  if (shouldWriteIaca) {
    const generatedIacaChain = getIACAChain();
    const generatedIacaCert = generatedIacaChain.certificate;
    const generatedIacaKey = generatedIacaChain.privateKey;

    writeFileSync(iacaCertPath, generatedIacaCert, { encoding: 'utf8', flag: 'w' });
    reportMessages.push(`- ${iacaCertExists ? 'Overwriting' : 'Creating'} IACA certificate at: ${iacaCertPath}`);
    writeFileSync(iacaKeyPath, generatedIacaKey, { encoding: 'utf8', flag: 'w' });
    reportMessages.push(`- ${iacaKeyExists ? 'Overwriting' : 'Creating'} IACA key at: ${iacaKeyPath}`);
  } else {
    reportMessages.push(
      `- IACA certificate and key already exist at: ${iacaCertPath}, ${iacaKeyPath} (skipped, use --force to regenerate)`
    );
  }

  emitter('CLI init completed\nSummary of actions:\n' + reportMessages.join('\n'));
}
