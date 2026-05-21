import type { Level } from '@itw-conformance-tool/logger';

// Types
export type ServiceCommand = 'init' | 'start';

export type LogLevel = Level;

export type Service = 'issuer' | 'rp';

// Interfaces
export interface CLIFlags {
  issuer: boolean;
  rp: boolean;
  all: boolean;
  force: boolean;
  config: {
    value: boolean;
    path: string;
  };
}
