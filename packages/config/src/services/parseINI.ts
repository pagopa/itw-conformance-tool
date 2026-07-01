import { existsSync, readFileSync } from 'node:fs';

import { parse } from 'ini';
import { z } from 'zod';

import {
  ConfigSchema,
  DEFAULT_CONFIG,
  GLOBAL_SECTION_DEFAULTS,
  ISSUER_SECTION_DEFAULTS,
  RP_SECTION_DEFAULTS
} from '../schemas/schemas.js';

import type { ParseINIReturn } from '../types/types.js';

const GlobalWithoutWalletSchema = z.preprocess(
  (input) => {
    if (input === undefined) {
      return GLOBAL_SECTION_DEFAULTS;
    }

    if (typeof input !== 'object' || input === null) {
      return input;
    }

    return {
      ...GLOBAL_SECTION_DEFAULTS,
      ...(input as Record<string, unknown>)
    };
  },
  z.object({
    data_dir: z.string().min(1).catch(GLOBAL_SECTION_DEFAULTS.data_dir),
    log_level: z.enum(['debug', 'info', 'warn', 'error']).catch(GLOBAL_SECTION_DEFAULTS.log_level),
    https: z.boolean().catch(GLOBAL_SECTION_DEFAULTS.https)
  })
);

const WalletProviderBackendUrlSchema = z.url();

/** Read config file and parse it into a valid one.
 *
 * @param iniPath - The path to the config file.
 * @returns A valid config object.
 */
export function parseINI(iniPath: string): ParseINIReturn {
  if (!existsSync(iniPath)) {
    return {
      ok: false,
      error: `Config file not found at path: ${iniPath}`,
      data: DEFAULT_CONFIG
    };
  }

  try {
    const rawConfigContent = readFileSync(iniPath, 'utf-8');
    const parsedConfig = parse(rawConfigContent);
    const parsedConfigRecord = parsedConfig as Record<string, unknown>;

    const globalSectionResult = GlobalWithoutWalletSchema.safeParse(parsedConfigRecord.global);
    const globalSection = globalSectionResult.success ? globalSectionResult.data : GLOBAL_SECTION_DEFAULTS;

    const issuerSectionResult = ConfigSchema.shape['itw-credential-issuer'].safeParse(
      parsedConfigRecord['itw-credential-issuer']
    );
    const issuerSection = issuerSectionResult.success ? issuerSectionResult.data : ISSUER_SECTION_DEFAULTS;

    const rpSectionResult = ConfigSchema.shape.rp.safeParse(parsedConfigRecord.rp);
    const rpSection = rpSectionResult.success ? rpSectionResult.data : RP_SECTION_DEFAULTS;

    const globalInput = parsedConfigRecord.global;
    const walletInput =
      typeof globalInput === 'object' && globalInput !== null
        ? (globalInput as Record<string, unknown>).wallet_provider_backend_url
        : undefined;
    const walletResult = WalletProviderBackendUrlSchema.safeParse(walletInput);

    if (!walletResult.success) {
      return {
        ok: false,
        error: 'Invalid config file: [global].wallet_provider_backend_url is required and must be a valid URL',
        data: {
          global: globalSection,
          'itw-credential-issuer': issuerSection,
          rp: rpSection
        }
      };
    }

    const result = ConfigSchema.safeParse({
      global: {
        ...globalSection,
        wallet_provider_backend_url: walletResult.data
      },
      'itw-credential-issuer': issuerSection,
      rp: rpSection
    });

    if (!result.success) {
      throw new Error(result.error.message);
    }

    return {
      ok: true,
      data: result.data
    };
  } catch (error: unknown) {
    return {
      ok: false,
      error: `Invalid config file: ${error instanceof Error ? error.message : JSON.stringify(error)}`,
      data: DEFAULT_CONFIG
    };
  }
}
