import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { ConfigINITemplate, parseINI, type ConfigType } from '@itw-conformance-tool/config';

import {
  getAuthRequestKey,
  getAuthResponseKey,
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

  const rpKeysExist = [false, false, false];

  const authRequestKeyPath = join(rpDirPath, 'auth-request-key.jwk.json');
  if (!existsFileSync(authRequestKeyPath) || flags.force) {
    const authRequestKey = getAuthRequestKey();
    writeFileSync(authRequestKeyPath, authRequestKey, { encoding: 'utf8', flag: 'w' });
  } else {
    rpKeysExist[0] = true;
  }

  const authResponseKeyPath = join(rpDirPath, 'auth-response-key.jwk.json');
  if (!existsFileSync(authResponseKeyPath) || flags.force) {
    const authResponseKey = getAuthResponseKey();
    writeFileSync(authResponseKeyPath, authResponseKey, { encoding: 'utf8', flag: 'w' });
  } else {
    rpKeysExist[1] = true;
  }

  const x5cCertPath = join(rpDirPath, 'x5c-cert.pem');
  if (!existsFileSync(x5cCertPath) || flags.force) {
    const x5cCert = getX5cCert();
    writeFileSync(x5cCertPath, x5cCert, { encoding: 'utf8', flag: 'w' });
  } else {
    rpKeysExist[2] = true;
  }

  if (rpKeysExist.every(Boolean)) {
    console.log(`⚠ Relying-party keys already exist → skipped (use --force to regenerate)`);
  } else {
    console.log(`✓ Generated relying-party keys → ${authRequestKeyPath}, ${authResponseKeyPath}, ${x5cCertPath}`);
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
