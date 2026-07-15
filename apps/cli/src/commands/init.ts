import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { ConfigIniTemplate, loadConfig, type ConfigSchemaType } from '@itw-conformance-tool/config';

import {
  createIntermediateCertificateFromJwk,
  createIssuerCertificateFromJwk,
  createSelfSignedCertificateFromJwk,
  createTrustAnchorCertificateFromJwk,
  selectEs256SigningJwk
} from '../utils/certificates.js';
import {
  getAuthRequestKey,
  getAuthResponseKey,
  getFederationKey,
  getIssuerIntermediateKey,
  getSigningKeys,
  getTrustAnchorFederationKey
} from '../utils/crypto.js';
import { existsFileSync } from '../utils/search.js';

import type { CliFlags } from '../types/types.js';

type InitConfig = {
  global: Pick<ConfigSchemaType['global'], 'data_dir' | 'log_level'>;
  'trust-anchor': Pick<ConfigSchemaType['trust-anchor'], 'entity_id'>;
  'credential-issuer': Pick<ConfigSchemaType['credential-issuer'], 'url'>;
};

/** Initializes the configuration file.
 *
 * @param flags - The command-line flags, which may include a `force` flag to overwrite existing configuration.
 * @returns The parsed configuration object.
 */
function checkConfig(flags: CliFlags): InitConfig {
  const configFilePath = resolve(process.cwd(), 'config.ini');
  if (!existsFileSync(configFilePath) || flags.force) {
    writeFileSync(configFilePath, ConfigIniTemplate, { encoding: 'utf8', flag: 'w' });
    process.stdout.write(`✓ ${flags.force ? 'Overwritten' : 'Created'} config.ini → ./config.ini\n`);
  } else {
    process.stdout.write(`✓ config.ini already exists → skipped (use --force to overwrite)\n`);
  }

  const rawConfigs = loadConfig({ configFilePath });
  const previousDataDir = rawConfigs.global.data_dir;
  const configs: InitConfig = {
    global: rawConfigs.global,
    'trust-anchor': rawConfigs['trust-anchor'],
    'credential-issuer': rawConfigs['credential-issuer']
  };
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
async function createFilesAndDirs(configs: InitConfig, flags: CliFlags): Promise<void> {
  const issuerDirPath = join(configs.global.data_dir, 'issuer');
  mkdirSync(issuerDirPath, { recursive: true });

  const rpDirPath = join(configs.global.data_dir, 'rp');
  mkdirSync(rpDirPath, { recursive: true });

  const trustAnchorDirPath = join(configs.global.data_dir, 'trust-anchor');
  mkdirSync(trustAnchorDirPath, { recursive: true });

  // The issuer certificate chain (below) is rooted at the trust-anchor federation
  // certificate, so the trust-anchor federation key/certificate must exist first.
  const trustAnchorFederationKeyPath = join(trustAnchorDirPath, 'federation-key.jwk.json');
  const trustAnchorFederationKeyGenerated = !existsFileSync(trustAnchorFederationKeyPath) || flags.force;
  if (trustAnchorFederationKeyGenerated) {
    const trustAnchorFederationKeyContent = getTrustAnchorFederationKey();
    writeFileSync(trustAnchorFederationKeyPath, trustAnchorFederationKeyContent, { encoding: 'utf8', flag: 'w' });
    process.stdout.write(`✓ Generated trust-anchor federation key → ${trustAnchorFederationKeyPath}\n`);
  } else {
    process.stdout.write(`⚠ Trust-anchor federation key already exists → skipped (use --force to regenerate)\n`);
  }

  const trustAnchorFederationCertPath = join(trustAnchorDirPath, 'federation-cert.pem');
  if (!existsFileSync(trustAnchorFederationCertPath) || flags.force || trustAnchorFederationKeyGenerated) {
    const trustAnchorFederationKeyContent = readFileSync(trustAnchorFederationKeyPath, 'utf8');
    const trustAnchorFederationKey = JSON.parse(trustAnchorFederationKeyContent) as Parameters<
      typeof createTrustAnchorCertificateFromJwk
    >[0];
    const commonName = new URL(configs['trust-anchor'].entity_id).hostname;
    const trustAnchorFederationCertificate = await createTrustAnchorCertificateFromJwk(
      trustAnchorFederationKey,
      commonName
    );

    writeFileSync(trustAnchorFederationCertPath, trustAnchorFederationCertificate, {
      encoding: 'utf8',
      flag: 'w'
    });
    process.stdout.write(`✓ Generated trust-anchor federation certificate → ${trustAnchorFederationCertPath}\n`);
  } else {
    process.stdout.write(
      `⚠ Trust-anchor federation certificate already exists → skipped (use --force to regenerate)\n`
    );
  }

  const signingKeysPath = join(issuerDirPath, 'jwks.json');
  const issuerSigningKeysGenerated = !existsFileSync(signingKeysPath) || flags.force;
  if (issuerSigningKeysGenerated) {
    const signingKeys = getSigningKeys();
    writeFileSync(signingKeysPath, signingKeys, { encoding: 'utf8', flag: 'w' });
    process.stdout.write(`✓ Generated issuer signing keys → ${signingKeysPath}\n`);
  } else {
    process.stdout.write(`⚠ Issuer keys already exist → skipped (use --force to regenerate)\n`);
  }

  const intermediateKeysPath = join(issuerDirPath, 'jwks-intermediate.json');
  const issuerIntermediateKeysGenerated = !existsFileSync(intermediateKeysPath) || flags.force;
  if (issuerIntermediateKeysGenerated) {
    const intermediateKeys = getIssuerIntermediateKey();
    writeFileSync(intermediateKeysPath, intermediateKeys, { encoding: 'utf8', flag: 'w' });
    process.stdout.write(`✓ Generated issuer intermediate signing keys → ${intermediateKeysPath}\n`);
  } else {
    process.stdout.write(`⚠ Issuer intermediate signing keys already exist → skipped (use --force to regenerate)\n`);
  }

  const intermediateCertPath = join(issuerDirPath, 'intermediate-cert.pem');
  const issuerIntermediateCertGenerated =
    !existsFileSync(intermediateCertPath) ||
    flags.force ||
    issuerIntermediateKeysGenerated ||
    trustAnchorFederationKeyGenerated;
  if (issuerIntermediateCertGenerated) {
    const intermediateJwks = JSON.parse(readFileSync(intermediateKeysPath, 'utf8')) as Parameters<
      typeof selectEs256SigningJwk
    >[0];
    const intermediateJwk = selectEs256SigningJwk(intermediateJwks);

    const trustAnchorFederationKey = JSON.parse(readFileSync(trustAnchorFederationKeyPath, 'utf8')) as Record<
      string,
      unknown
    >;
    const trustAnchorFederationCertificatePem = readFileSync(trustAnchorFederationCertPath, 'utf8');

    const intermediateCertificate = await createIntermediateCertificateFromJwk(
      intermediateJwk,
      trustAnchorFederationKey,
      trustAnchorFederationCertificatePem
    );

    writeFileSync(intermediateCertPath, intermediateCertificate, { encoding: 'utf8', flag: 'w' });
    process.stdout.write(`✓ Generated issuer intermediate certificate → ${intermediateCertPath}\n`);
  } else {
    process.stdout.write(`⚠ Issuer intermediate certificate already exists → skipped (use --force to regenerate)\n`);
  }

  const issuerCertPath = join(issuerDirPath, 'cert.pem');
  if (
    !existsFileSync(issuerCertPath) ||
    flags.force ||
    issuerSigningKeysGenerated ||
    issuerIntermediateKeysGenerated ||
    issuerIntermediateCertGenerated
  ) {
    const signingJwks = JSON.parse(readFileSync(signingKeysPath, 'utf8')) as Parameters<
      typeof selectEs256SigningJwk
    >[0];
    const issuerSigningJwk = selectEs256SigningJwk(signingJwks);

    const intermediateJwks = JSON.parse(readFileSync(intermediateKeysPath, 'utf8')) as Parameters<
      typeof selectEs256SigningJwk
    >[0];
    const intermediateJwk = selectEs256SigningJwk(intermediateJwks);

    const intermediateCertificatePem = readFileSync(intermediateCertPath, 'utf8');

    const issuerCertificate = await createIssuerCertificateFromJwk(
      issuerSigningJwk,
      intermediateJwk,
      intermediateCertificatePem,
      configs['credential-issuer'].url
    );

    writeFileSync(issuerCertPath, issuerCertificate, { encoding: 'utf8', flag: 'w' });
    process.stdout.write(`✓ Generated issuer certificate → ${issuerCertPath}\n`);
  } else {
    process.stdout.write(`⚠ Issuer certificate already exists → skipped (use --force to regenerate)\n`);
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
export async function init(flags: CliFlags): Promise<void> {
  const configs = checkConfig(flags);
  await createFilesAndDirs(configs, flags);
}
