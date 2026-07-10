import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { ConfigIniTemplate, parseConfigIni, type ConfigSchemaType } from '@itw-conformance-tool/config';

import { createSelfSignedCertificateFromJwk, getIACAChain } from '../utils/certificates.js';
import { getAuthRequestKey, getAuthResponseKey, getFederationKey, getSigningKeys } from '../utils/crypto.js';
import { expandPath } from '../utils/path.js';
import { existsFileSync } from '../utils/search.js';

import type { CLIFlags } from '../types/types.js';

type InitConfig = {
  global: Pick<ConfigSchemaType['global'], 'data_dir' | 'https' | 'log_level'>;
};

/** Initializes the configuration file.
 *
 * @param flags - The command-line flags, which may include a `force` flag to overwrite existing configuration.
 * @returns The parsed configuration object.
 */
function checkConfig(flags: CLIFlags): InitConfig {
  const configFilePath = resolve(process.cwd(), 'config.ini');
  if (!existsFileSync(configFilePath) || flags.force) {
    writeFileSync(configFilePath, ConfigIniTemplate, { encoding: 'utf8', flag: 'w' });
    process.stdout.write(`✓ ${flags.force ? 'Overwritten' : 'Created'} config.ini → ./config.ini\n`);
  } else {
    process.stdout.write(`✓ config.ini already exists → skipped (use --force to overwrite)\n`);
  }

  const configs = parseConfigIni(configFilePath);
  const previousDataDir = configs.global.data_dir;
  configs.global.data_dir = expandPath(configs.global.data_dir);

  const dataDirExists = existsSync(configs.global.data_dir) && statSync(configs.global.data_dir).isDirectory();
  mkdirSync(configs.global.data_dir, { recursive: true });
  if (!dataDirExists || flags.force) {
    process.stdout.write(`✓ ${flags.force ? 'Overwritten' : 'Created'} data_dir → ${previousDataDir}\n`);
  }

  return configs;
}

/** Creates necessary mandatory directories and files.
 *
 * @param configs - The parsed configuration object.
 * @param flags - The command-line flags.
 * @returns It performs file system operations to create directories and files as needed based on the configuration and flags.
 */
async function createFilesAndDirs(configs: InitConfig, flags: CLIFlags): Promise<void> {
  const issuerDirPath = join(configs.global.data_dir, 'issuer');
  mkdirSync(issuerDirPath, { recursive: true });

  const rpDirPath = join(configs.global.data_dir, 'rp');
  mkdirSync(rpDirPath, { recursive: true });

  const iacaCertPath = join(issuerDirPath, 'iaca-cert.pem');
  const iacaKeyPath = join(issuerDirPath, 'iaca-key.pem');
  if (!(existsFileSync(iacaCertPath) && existsFileSync(iacaKeyPath)) || flags.force) {
    const generatedIacaChain = await getIACAChain();
    const generatedIacaCert = generatedIacaChain.certificate;
    const generatedIacaKey = generatedIacaChain.privateKey;

    writeFileSync(iacaCertPath, generatedIacaCert, { encoding: 'utf8', flag: 'w' });
    writeFileSync(iacaKeyPath, generatedIacaKey, { encoding: 'utf8', flag: 'w' });

    process.stdout.write(`✓ Generated mock IACA certificates → ${iacaCertPath}\n`);
  }

  const signingKeysPath = join(issuerDirPath, 'signing-keys.jwks.json');
  if (!existsFileSync(signingKeysPath) || flags.force) {
    const signingKeys = getSigningKeys();
    writeFileSync(signingKeysPath, signingKeys, { encoding: 'utf8', flag: 'w' });
    process.stdout.write(`✓ Generated issuer signing keys → ${signingKeysPath}\n`);
  } else {
    process.stdout.write(`⚠ Issuer keys already exist → skipped (use --force to regenerate)\n`);
  }

  const rpArtifacts = [
    ['auth-request-key.jwk.json', getAuthRequestKey],
    ['auth-response-key.jwk.json', getAuthResponseKey],
    ['federation-key.jwk.json', getFederationKey]
  ] as const;

  const generatedRpPaths: string[] = [];
  let authRequestKeyContent: string | undefined;

  for (const [fileName, factory] of rpArtifacts) {
    const filePath = join(rpDirPath, fileName);
    if (!existsFileSync(filePath) || flags.force) {
      const content = factory();
      writeFileSync(filePath, content, { encoding: 'utf8', flag: 'w' });
      if (fileName === 'auth-request-key.jwk.json') {
        authRequestKeyContent = content;
      }
      generatedRpPaths.push(filePath);
    }
  }

  const x5cCertPath = join(rpDirPath, 'x5c-cert.pem');
  if (!existsFileSync(x5cCertPath) || flags.force) {
    if (!authRequestKeyContent) {
      const authRequestKeyPath = join(rpDirPath, 'auth-request-key.jwk.json');
      authRequestKeyContent = readFileSync(authRequestKeyPath, 'utf8');
    }

    const authRequestKey = JSON.parse(authRequestKeyContent) as Parameters<
      typeof createSelfSignedCertificateFromJwk
    >[0];
    const x5cCertificate = await createSelfSignedCertificateFromJwk(authRequestKey);
    writeFileSync(x5cCertPath, x5cCertificate, { encoding: 'utf8', flag: 'w' });
    generatedRpPaths.push(x5cCertPath);
  }

  if (generatedRpPaths.length === 0) {
    process.stdout.write(`⚠ Relying-party keys already exist → skipped (use --force to regenerate)\n`);
  } else {
    process.stdout.write(`✓ Generated relying-party keys → ${generatedRpPaths.join(', ')}\n`);
  }
}

/** Initializes the configuration file and necessary keys/certificates for the conformance tool.
 *
 * @param flags - The command-line flags.
 * @returns It performs file system operations and exits the process upon completion.
 */
export async function init(flags: CLIFlags): Promise<void> {
  const configs = checkConfig(flags);
  await createFilesAndDirs(configs, flags);
}
