import { Buffer } from 'node:buffer';
import { webcrypto } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { networkInterfaces } from 'node:os';
import { join } from 'node:path';

import * as x509 from '@peculiar/x509';

const CERTIFICATE_SIGNING_ALGORITHM = {
  hash: 'SHA-256',
  name: 'ECDSA'
} as const;

const KEY_PAIR_ALGORITHM = {
  name: 'ECDSA',
  namedCurve: 'P-256'
} as const;

const CERTIFICATE_VALIDITY_MS = 365 * 24 * 60 * 60 * 1000;
const ROOT_CA_VALIDITY_MS = 5 * 365 * 24 * 60 * 60 * 1000;

/** Subject of the local root CA that signs every service TLS certificate. */
export const LOCAL_ROOT_CA_SUBJECT = 'CN=IT Wallet Conformance Tool Local CA';

/** Directory, relative to `data_dir`, holding the local root CA and its device bundles. */
export const TLS_DIRECTORY_NAME = 'tls';

export const ROOT_CA_CERTIFICATE_FILENAME = 'ca-cert.pem';
export const ROOT_CA_PRIVATE_KEY_FILENAME = 'ca-key.pem';

/** Host names always present in generated leaf certificates.
 *
 * `10.0.2.2` is the alias through which the Android emulator reaches the host
 * loopback interface, so an emulator can validate the services without any
 * additional certificate material.
 */
const DEFAULT_LEAF_HOSTNAMES = ['localhost', '127.0.0.1', '::1', '10.0.2.2'];

export interface RuntimeHttpsOptions {
  ca: string;
  cert: string;
  key: string;
}

/** A PEM-encoded root certificate authority persisted under `<data_dir>/tls`. */
export interface LocalRootCertificateAuthority {
  certificatePem: string;
  privateKeyPem: string;
}

export interface CreateHttpsOptionsInput {
  /** Data directory holding the persistent local root CA. When it contains a
   * root CA, the generated leaf certificate chains to it; otherwise an
   * ephemeral CA is created for this process only. */
  dataDir?: string;
  /** Additional DNS names or IP addresses to add to the leaf certificate SAN. */
  hostnames?: string[];
}

function encodePem(label: string, data: ArrayBuffer): string {
  const base64 = Buffer.from(data).toString('base64');
  const body = base64.match(/.{1,64}/g)?.join('\n') ?? '';

  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

function decodePem(pem: string): ArrayBuffer {
  const base64 = pem.replace(/-----(BEGIN|END)[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Buffer.from(base64, 'base64');

  return der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer;
}

/** Returns the routable addresses of the host, so that a physical device on the
 * same network can validate the services when `config.ini` points at a LAN
 * address instead of the loopback interface.
 *
 * Link-local addresses are skipped: no device reaches the services through
 * them, and they would only pad the certificate's SAN list.
 */
function getLocalNetworkAddresses(): string[] {
  return Object.values(networkInterfaces())
    .flatMap((addresses) => addresses ?? [])
    .filter((address) => !address.internal)
    .map((address) => address.address)
    .filter((address) => isIP(address) !== 0)
    .filter((address) => !/^(169\.254\.|fe80:)/i.test(address));
}

/** Returns the paths of the local root CA material inside a data directory.
 *
 * @param dataDir - The configured `data_dir`.
 * @returns The TLS directory and the root CA certificate and private key paths.
 */
export function getLocalRootCaPaths(dataDir: string): {
  certificatePath: string;
  directory: string;
  privateKeyPath: string;
} {
  const directory = join(dataDir, TLS_DIRECTORY_NAME);

  return {
    certificatePath: join(directory, ROOT_CA_CERTIFICATE_FILENAME),
    directory,
    privateKeyPath: join(directory, ROOT_CA_PRIVATE_KEY_FILENAME)
  };
}

/** Creates the local root certificate authority that signs the TLS certificate
 * of every local service.
 *
 * It is generated once by `itwct init` and persisted so that it can be
 * installed as a trusted root on Android devices and iOS simulators.
 *
 * @returns The PEM-encoded root CA certificate and its PKCS#8 private key.
 */
export async function createLocalRootCertificateAuthority(): Promise<LocalRootCertificateAuthority> {
  const now = new Date();
  const notAfter = new Date(now.getTime() + ROOT_CA_VALIDITY_MS);

  const caKeys = await webcrypto.subtle.generateKey(KEY_PAIR_ALGORITHM, true, ['sign', 'verify']);

  const caCertificate = await x509.X509CertificateGenerator.createSelfSigned(
    {
      keys: caKeys,
      name: LOCAL_ROOT_CA_SUBJECT,
      notAfter,
      notBefore: now,
      signingAlgorithm: CERTIFICATE_SIGNING_ALGORITHM,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
        await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey)
      ]
    },
    webcrypto
  );

  const privateKey = await webcrypto.subtle.exportKey('pkcs8', caKeys.privateKey);

  return {
    certificatePem: caCertificate.toString('pem'),
    privateKeyPem: encodePem('PRIVATE KEY', privateKey)
  };
}

/** Reads the local root certificate authority from a data directory.
 *
 * @param dataDir - The configured `data_dir`.
 * @returns The root CA material, or `undefined` when it has not been generated.
 */
export function readLocalRootCertificateAuthority(dataDir: string): LocalRootCertificateAuthority | undefined {
  const { certificatePath, privateKeyPath } = getLocalRootCaPaths(dataDir);
  if (!existsSync(certificatePath) || !existsSync(privateKeyPath)) {
    return undefined;
  }

  return {
    certificatePem: readFileSync(certificatePath, 'utf8'),
    privateKeyPem: readFileSync(privateKeyPath, 'utf8')
  };
}

async function importRootCaSigningKey(privateKeyPem: string): Promise<webcrypto.CryptoKey> {
  return webcrypto.subtle.importKey('pkcs8', decodePem(privateKeyPem), KEY_PAIR_ALGORITHM, true, ['sign']);
}

/** Creates the HTTPS options used by a local Fastify service.
 *
 * When the data directory contains the root CA generated by `itwct init`, the
 * server certificate chains to it, so a device that trusts the root CA trusts
 * every local service. Without it, a throwaway CA is generated in memory and
 * the certificate is trusted by nothing.
 *
 * @param input - The data directory holding the root CA and extra SAN entries.
 * @returns The Fastify `https` options: private key, leaf certificate, and root CA.
 */
export async function createHttpsOptions({
  dataDir,
  hostnames = []
}: CreateHttpsOptionsInput = {}): Promise<RuntimeHttpsOptions> {
  const now = new Date();
  const notAfter = new Date(now.getTime() + CERTIFICATE_VALIDITY_MS);

  const rootCa = dataDir === undefined ? undefined : readLocalRootCertificateAuthority(dataDir);

  let caCertificate: x509.X509Certificate;
  let caSigningKey: webcrypto.CryptoKey;

  if (rootCa) {
    caCertificate = new x509.X509Certificate(rootCa.certificatePem);
    caSigningKey = await importRootCaSigningKey(rootCa.privateKeyPem);
  } else {
    const caKeys = await webcrypto.subtle.generateKey(KEY_PAIR_ALGORITHM, true, ['sign', 'verify']);
    caCertificate = await x509.X509CertificateGenerator.createSelfSigned(
      {
        keys: caKeys,
        name: LOCAL_ROOT_CA_SUBJECT,
        notAfter,
        notBefore: now,
        signingAlgorithm: CERTIFICATE_SIGNING_ALGORITHM,
        extensions: [
          new x509.BasicConstraintsExtension(true, 0, true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
          await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey)
        ]
      },
      webcrypto
    );
    caSigningKey = caKeys.privateKey;
  }

  const serverKeys = await webcrypto.subtle.generateKey(KEY_PAIR_ALGORITHM, true, ['sign', 'verify']);

  const subjectAlternativeNames = [
    ...new Set([...DEFAULT_LEAF_HOSTNAMES, ...hostnames, ...getLocalNetworkAddresses()])
  ];

  const certificate = await x509.X509CertificateGenerator.create(
    {
      issuer: caCertificate.subject,
      notAfter,
      notBefore: now,
      publicKey: serverKeys.publicKey,
      signingAlgorithm: CERTIFICATE_SIGNING_ALGORITHM,
      signingKey: caSigningKey,
      subject: 'CN=localhost',
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement, true),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth], true),
        new x509.SubjectAlternativeNameExtension(
          subjectAlternativeNames.map((name) => ({ type: isIP(name) === 0 ? 'dns' : 'ip', value: name }))
        ),
        await x509.AuthorityKeyIdentifierExtension.create(caCertificate.publicKey, false, webcrypto),
        await x509.SubjectKeyIdentifierExtension.create(serverKeys.publicKey)
      ]
    },
    webcrypto
  );

  const key = await webcrypto.subtle.exportKey('pkcs8', serverKeys.privateKey);

  return {
    ca: caCertificate.toString('pem'),
    cert: certificate.toString('pem'),
    key: encodePem('PRIVATE KEY', key)
  };
}
