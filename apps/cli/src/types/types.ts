import type { Level } from '@itw-conformance-tool/logger';

// Types
export type EmitLog = (event: string, level?: Level) => void;

export type LogLevel = Level;

export type Service = 'issuer' | 'rp';

export type ServiceCommand = 'init' | 'start';

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

export interface ServiceProcess {
  prefix: string;
  nxArgs: string[];
}