import type forge from 'node-forge';
import type { JsonWebKey } from 'node:crypto';

// Types
export {
  type EncryptJweCallback,
  type DecryptJweCallback,
  type GenerateRandomCallback,
  type HashAlgorithm,
  type Jwk,
  type SignJwtCallback,
  type VerifyJwtCallback
} from '@pagopa/io-wallet-oauth2';

export type ForgeAttribute = { name: string; value: string } | { shortName: string; value: string };

export type GenerateKeyMaterialOptions =
  | {
      use: 'sig';
      keyType: KeyType;
      alg?: string;
      modulusLength?: number;
      namedCurve?: 'P-256' | 'P-384' | 'P-521';
    }
  | {
      use: 'enc';
      keyType: 'rsa' | 'ec';
      alg?: string;
      modulusLength?: number;
      namedCurve?: 'P-256' | 'P-384' | 'P-521';
    };

export type JwkRecord = Record<string, unknown>;

export type KeyType = 'rsa' | 'ec' | 'ed25519';

export type KeyUse = 'sig' | 'enc';

// Interfaces
export interface CertificateParams {
  subject: ForgeAttribute[];
  issuer: ForgeAttribute[];
  publicKey: forge.pki.rsa.PublicKey;
  issuerPrivateKey: forge.pki.rsa.PrivateKey;
  serialNumber: string;
  isCA?: boolean;
}

export interface GenerateKeyPairResult {
  privateKey: forge.pki.rsa.PrivateKey;
  publicKey: forge.pki.rsa.PublicKey;
  privateKeyPem: string;
  publicKeyPem: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
}

export interface IacaChain {
  certificate: string;
  privateKey: string;
}

export interface IacaChainParams {
  commonName?: string;
  countryName?: string;
  organizationName?: string;
  serialNumber?: string;
}

export interface JwkDescriptor {
  kid: string;
  use: KeyUse;
  alg: 'ES256' | 'ECDH-ES';
  keyOps: string[];
}

export interface JwkGenerationSpec {
  alg: string;
  use: KeyUse;
  count?: number;
  keyOps?: string[];
  kid?: string;
  kidPrefix?: string;
  extractable?: boolean;
}

export interface GenerateJwksOptions {
  keys: JwkGenerationSpec[];
}

export interface GenerateKeyMaterialResult {
  alg: string;
  use: KeyUse;
  kid: string;
  keyOps: string[];
  privateJwk: JwkRecord;
  publicJwk: JwkRecord;
  privateKeyPem?: string;
  publicKeyPem?: string;
}

export interface JwkSet {
  keys: JwkRecord[];
}

export interface KeyDescriptor {
  kid: string;
  use: KeyUse;
}

export interface TlsCertAndKey {
  cert: string;
  key: string;
}

export interface TlsCertParams {
  commonName?: string;
  organizationName?: string;
  altNames?: string[];
}

export interface X5cCertParams {
  commonName?: string;
  organizationName?: string;
}
