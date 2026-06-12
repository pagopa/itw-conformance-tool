import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { ConfigINITemplate, parseINI, type ConfigType } from '@itw-conformance-tool/config';

import {
  getAuthRequestKey,
  getAuthResponseKey,
  getFederationKey,
  getIACAChain,
  getSigningKeys,
  getTlsCertAndKey,
  getX5cCert
} from '../utils/crypto.js';
import { expandPath } from '../utils/path.js';
import { existsFileSync } from '../utils/search.js';

import type { CLIFlags } from '../types/types.js';

/** Initializes the configuration file.
 *
 * @param flags - The command-line flags, which may include a `force` flag to overwrite existing configuration.
 * @returns The parsed configuration object.
 */
function checkConfig(flags: CLIFlags): ConfigType {
  const configFilePath = resolve(process.cwd(), 'config.ini');
  if (!existsFileSync(configFilePath) || flags.force) {
    writeFileSync(configFilePath, ConfigINITemplate, { encoding: 'utf8', flag: 'w' });

    console.log(`✓ ${flags.force ? 'Overwritten' : 'Created'} config.ini → ./config.ini`);
  } else {
    console.log(`✓ config.ini already exists → skipped (use --force to overwrite)`);
  }

  const configs = parseINI(configFilePath).data;
  const previousDataDir = configs.global.data_dir;
  configs.global.data_dir = expandPath(configs.global.data_dir);

  const dataDirExists = existsSync(configs.global.data_dir) && statSync(configs.global.data_dir).isDirectory();
  mkdirSync(configs.global.data_dir, { recursive: true });
  if (!dataDirExists || flags.force) {
    console.log(`✓ ${flags.force ? 'Overwritten' : 'Created'} data_dir → ${previousDataDir}`);
  }

  return configs;
}

/** Creates necessary mandatory directories and files.
 *
 * @param configs - The parsed configuration object.
 * @param flags - The command-line flags.
 * @returns It performs file system operations to create directories and files as needed based on the configuration and flags.
 */
function createFilesAndDirs(configs: ConfigType, flags: CLIFlags): void {
  const issuerDirPath = join(configs.global.data_dir, 'issuer');
  mkdirSync(issuerDirPath, { recursive: true });

  const rpDirPath = join(configs.global.data_dir, 'rp');
  mkdirSync(rpDirPath, { recursive: true });

  const tlsCertPath = join(configs.global.data_dir, 'tls-cert.pem');
  const tlsKeyPath = join(configs.global.data_dir, 'tls-key.pem');
  if (configs.global.https && (!(existsFileSync(tlsCertPath) && existsFileSync(tlsKeyPath)) || flags.force)) {
    const generatedTls = getTlsCertAndKey();
    writeFileSync(tlsCertPath, generatedTls.cert, { encoding: 'utf8', flag: 'w' });
    writeFileSync(tlsKeyPath, generatedTls.key, { encoding: 'utf8', flag: 'w' });

    console.log(`✓ Generated local TLS certificate → ${tlsCertPath}`);
  }

  const iacaCertPath = join(issuerDirPath, 'iaca-cert.pem');
  const iacaKeyPath = join(issuerDirPath, 'iaca-key.pem');
  if (!(existsFileSync(iacaCertPath) && existsFileSync(iacaKeyPath)) || flags.force) {
    const generatedIacaChain = getIACAChain();
    const generatedIacaCert = generatedIacaChain.certificate;
    const generatedIacaKey = generatedIacaChain.privateKey;

    writeFileSync(iacaCertPath, generatedIacaCert, { encoding: 'utf8', flag: 'w' });
    writeFileSync(iacaKeyPath, generatedIacaKey, { encoding: 'utf8', flag: 'w' });

    console.log(`✓ Generated mock IACA certificates → ${iacaCertPath}`);
  }

  const signingKeysPath = join(issuerDirPath, 'signing-keys.jwks.json');
  if (!existsFileSync(signingKeysPath) || flags.force) {
    const signingKeys = getSigningKeys();
    writeFileSync(signingKeysPath, signingKeys, { encoding: 'utf8', flag: 'w' });
    console.log(`✓ Generated issuer signing keys → ${signingKeysPath}`);
  } else {
    console.log(`⚠ Issuer keys already exist → skipped (use --force to regenerate)`);
  }

  const rpArtifacts = [
    ['auth-request-key.jwk.json', getAuthRequestKey],
    ['auth-response-key.jwk.json', getAuthResponseKey],
    ['federation-key.jwk.json', getFederationKey],
    ['x5c-cert.pem', getX5cCert]
  ] as const;

  const generatedRpPaths: string[] = [];

  for (const [fileName, factory] of rpArtifacts) {
    const filePath = join(rpDirPath, fileName);
    if (!existsFileSync(filePath) || flags.force) {
      writeFileSync(filePath, factory(), { encoding: 'utf8', flag: 'w' });
      generatedRpPaths.push(filePath);
    }
  }

  if (generatedRpPaths.length === 0) {
    console.log(`⚠ Relying-party keys already exist → skipped (use --force to regenerate)`);
  } else {
    console.log(`✓ Generated relying-party keys → ${generatedRpPaths.join(', ')}`);
  }
}

/** Initializes the configuration file and necessary keys/certificates for the conformance tool.
 *
 * @param flags - The command-line flags.
 * @returns It performs file system operations and exits the process upon completion.
 */
export function init(flags: CLIFlags): void {
  const configs = checkConfig(flags);
  createFilesAndDirs(configs, flags);
}
