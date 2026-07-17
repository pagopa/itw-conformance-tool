import type { Level } from '@itw-conformance-tool/logger';

// Types
export type EmitLog = (event: string, level?: Level) => void;

export type LogLevel = Level;

export type SearchParamResult = {
  value: string;
  remainingArgs: string[];
};

export type Service = 'issuer' | 'rp' | 'trust-anchor';

export type ServiceCommand = 'init' | 'start';

// Interfaces
export interface InitFlags {
  force: boolean;
}

export interface StartFlags {
  all: boolean;
  issuer: boolean;
  rp: boolean;
  trustAnchor: boolean;
}

export interface ServiceProcess {
  prefix: string;
  nxArgs: string[];
}
