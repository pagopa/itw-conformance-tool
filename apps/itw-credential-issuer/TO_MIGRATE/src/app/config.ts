import { setGlobalConfig } from '@pagopa/io-wallet-utils';
import { z } from 'zod';

import { ECPrivateKeyWithKid } from '../domain/z-jwk';

export type Config = Readonly<{
  baseURL: string;
  cert: Readonly<{
    iacaX509: string;
  }>;
  cosmosdb: Readonly<{
    databaseName: string;
    endpoint: string;
    key?: string;
  }>;
  encrypter: Readonly<{
    jwks: ECPrivateKeyWithKid[];
  }>;
  isDevelopment: boolean;
  signer: Readonly<{
    jwks: ECPrivateKeyWithKid[];
  }>;
}>;

const EnvsCodec = z
  .object({
    BASE_URL: z.string(),
    COSMOSDB_DATABASE_NAME: z.string(),
    COSMOSDB_ENDPOINT: z.string(),
    COSMOSDB_KEY: z.string().optional(),
    IACA_X509_BASE64: z.string(),
    NODE_ENV: z.literal('development').or(z.literal('production')),
    SIGNER_JWK_LIST_BASE64: z.string()
  })
  .superRefine((envs, ctx) => {
    if (envs.NODE_ENV === 'development' && !envs.COSMOSDB_KEY) {
      ctx.addIssue({
        code: 'custom',
        message: 'COSMOSDB_KEY is required in non-production environments when not using Managed Identity.',
        path: ['COSMOSDB_KEY']
      });
    }
  });

/**
 * Read the application configuration and check for invalid values.
 *
 * @returns either the configuration values or an Error
 */
const getConfigOrError = (envs: Record<string, string | undefined>): Config => {
  const envCodec = EnvsCodec.parse(envs);

  const binary = Buffer.from(envCodec.SIGNER_JWK_LIST_BASE64, 'base64').toString('binary');

  const jwks = JSON.parse(binary) as readonly ECPrivateKeyWithKid[];

  return {
    baseURL: envCodec.BASE_URL,
    cert: {
      iacaX509: envCodec.IACA_X509_BASE64
    },
    cosmosdb: {
      databaseName: envCodec.COSMOSDB_DATABASE_NAME,
      endpoint: envCodec.COSMOSDB_ENDPOINT,
      key: envCodec.COSMOSDB_KEY
    },
    encrypter: {
      jwks: jwks.filter((key) => key.use === 'enc')
    },
    isDevelopment: envCodec.NODE_ENV === 'development',
    signer: {
      jwks: jwks.filter((key) => key.use === 'sig')
    }
  };
};

// Export the config as singleton to be used across modules
export const config = getConfigOrError(process.env);

setGlobalConfig({
  allowInsecureUrls: config.isDevelopment
});
