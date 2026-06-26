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

export type TestType = 'issuance' | 'presentation' | 'wallet-provider-backend';

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
  runId: string | undefined;
  format: 'html' | 'pdf';
  testType: TestType;
}

export interface ServiceProcess {
  prefix: string;
  nxArgs: string[];
}
