import pino, { type Logger, type LoggerOptions } from 'pino';

import type { CreateLoggerOptions } from '../types/types.js';

/** Predefined logger options that set the log level
 * based on the environment and configure the timestamp format.
 */
export const loggerOptions: LoggerOptions = {
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  timestamp: pino.stdTimeFunctions.isoTimeNano,
  transport:
    process.env.NODE_ENV === 'production'
      ? undefined
      : {
          target: 'pino-pretty',
          options: {
            colorize: true,
            singleLine: true
          }
        }
};

/** Create a new logger instance with the specified options.
 * The logger will use the provided log level and bindings, or
 * default to the predefined logger options if not specified.
 *
 * @param options - An object containing optional configuration for the logger, including:
 *   - level: The log level to use (e.g., 'debug', 'info', 'warn', 'error').
 *   - bindings: An object containing additional properties to bind to each log message.
 * @returns A new logger instance configured with the specified options.
 */
export function createLogger(options: CreateLoggerOptions = {}): Logger {
  const { level, bindings } = options;
  const effectiveLoggerOptions: LoggerOptions = level === undefined ? loggerOptions : { ...loggerOptions, level };
  const baseLogger = pino(effectiveLoggerOptions);

  return bindings === undefined ? baseLogger : baseLogger.child(bindings);
}

export const logger: Logger = createLogger();
