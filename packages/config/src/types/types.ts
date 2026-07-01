import { z } from 'zod';

import type { ConfigSchema, DEFAULT_CONFIG } from '../schemas/schemas.js';

// Types
export type ConfigType = z.infer<typeof ConfigSchema>;
export type DefaultConfigType = typeof DEFAULT_CONFIG;
export type FallbackConfigType = {
  global: Omit<ConfigType['global'], 'wallet_provider_backend_url'>;
  'itw-credential-issuer': ConfigType['itw-credential-issuer'];
  rp: ConfigType['rp'];
};

export type ParseINIReturn = { ok: true; data: ConfigType } | { ok: false; error: string; data: FallbackConfigType };
