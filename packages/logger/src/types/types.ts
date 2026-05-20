import type { LoggerOptions } from 'pino';

// Interfaces
export interface CreateLoggerOptions {
  level?: LoggerOptions['level'];
  bindings?: Record<string, unknown>;
}
