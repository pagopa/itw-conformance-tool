import z from 'zod';

import type { ConfigSchema } from '../schemas/schemas.js';

// Types
export type ConfigType = z.infer<typeof ConfigSchema>;

export type ParseINIReturn = { ok: true; data: ConfigType } | { ok: false; error: string; data: ConfigType };
