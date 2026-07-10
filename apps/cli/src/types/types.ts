import type { Level } from '@itw-conformance-tool/logger';

// Types
export type EmitLog = (event: string, level?: Level) => void;

export type LogLevel = Level;

export type SearchParamResult = {
  value: string;
  remainingArgs: string[];
};

export type Service = 'issuer' | 'rp';

export type ServiceCommand = 'init' | 'start';

// Interfaces
export interface CliFlags {
  issuer: boolean;
  rp: boolean;
  all: boolean;
  force: boolean;
  config: {
    value: boolean;
    path: string;
  };
  runId: string | undefined;
  format: 'html' | 'pdf';
}

export interface ServiceProcess {
  prefix: string;
  nxArgs: string[];
}
