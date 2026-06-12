import type forge from 'node-forge';

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

export type KeyUse = 'sig' | 'enc';

export type JwkRecord = Record<string, unknown>;

// Interfaces
export interface CertificateParams {
  subject: ForgeAttribute[];
  issuer: ForgeAttribute[];
  publicKey: forge.pki.rsa.PublicKey;
  issuerPrivateKey: forge.pki.rsa.PrivateKey;
  serialNumber: string;
  isCA?: boolean;
}

export interface IacaChain {
  certificate: string;
  privateKey: string;
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
  prettyPrint?: boolean;
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
