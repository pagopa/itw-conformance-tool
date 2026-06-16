import { generateKeyPairSync } from 'node:crypto';

import type { GenerateKeyMaterialOptions } from '../types/types.js';

const ALGORITHM_MATRIX = {
  sig: {
    rsa: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
    ec: ['ES256', 'ES384', 'ES512'],
    ed25519: ['EdDSA']
  },
  enc: {
    rsa: ['RSA-OAEP', 'RSA-OAEP-256'],
    ec: ['ECDH-ES', 'ECDH-ES+A256KW']
  }
} as const;

const ALGORITHM_TO_CURVE = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521'
} as const;

const DEFAULT_ALGORITHMS = {
  sig: {
    rsa: 'RS256',
    ec: 'ES256',
    ed25519: 'EdDSA'
  },
  enc: {
    rsa: 'RSA-OAEP-256',
    ec: 'ECDH-ES+A256KW'
  }
} as const;

/** Resolves the algorithm to use based on provided options,
 * applying defaults if necessary.
 *
 * @param options - The key generation options containing use and key type
 * @returns The resolved algorithm name to use for key generation
 */
function resolveDefaultAlg(options: GenerateKeyMaterialOptions): string {
  if (options.alg) return options.alg;

  const defaults = DEFAULT_ALGORITHMS[options.use];
  const alg = defaults[options.keyType as keyof typeof defaults];

  if (!alg) {
    throw new Error(`No default algorithm for ${options.use}/${options.keyType}`);
  }

  return alg;
}

/** Validates that the selected algorithm is compatible with
 * the specified key type and use.
 *
 * @param options - The key generation options containing use and key type
 * @param alg - The resolved algorithm to validate
 */
function validatekeysTypeCombination(options: GenerateKeyMaterialOptions, alg: string): void {
  const useMatrix = ALGORITHM_MATRIX[options.use];
  const supported = useMatrix[options.keyType as keyof typeof useMatrix] as readonly string[];

  if (!supported?.includes(alg)) {
    throw new Error(`Algorithm '${alg}' not valid for ${options.use}/${options.keyType}`);
  }
}

/** Generate an asymmetric key pair for signing or encryption.
 *
 * @param options - Configuration object specifying key type,
 * use case, and optional algorithm/curve
 * @returns KeyObject pair { privateKey, publicKey }
 */
export function generateKeyPair(options: GenerateKeyMaterialOptions) {
  const alg = resolveDefaultAlg(options);
  validatekeysTypeCombination(options, alg);

  // RSA algorithms
  if (['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'RSA-OAEP', 'RSA-OAEP-256'].includes(alg)) {
    return generateKeyPairSync('rsa', {
      modulusLength: options.modulusLength ?? 2048
    });
  }

  // ES256/384/512 with standard curves
  if (alg in ALGORITHM_TO_CURVE) {
    return generateKeyPairSync('ec', {
      namedCurve: ALGORITHM_TO_CURVE[alg as keyof typeof ALGORITHM_TO_CURVE]
    });
  }

  // ECDH algorithms with configurable curve
  if (['ECDH-ES', 'ECDH-ES+A256KW'].includes(alg)) {
    return generateKeyPairSync('ec', {
      namedCurve: options.namedCurve ?? 'P-256'
    });
  }

  // EdDSA
  if (alg === 'EdDSA') {
    return generateKeyPairSync('ed25519');
  }

  throw new Error(`Unsupported algorithm '${alg}'`);
}
