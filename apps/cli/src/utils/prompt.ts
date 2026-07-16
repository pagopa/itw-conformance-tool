import { type Logger, type Level } from '@itw-conformance-tool/logger';

/** Utility functions for the CLI, including logger creation.
 *
 * @param logger - A logger instance used for emitting structured log messages.
 * @returns A function that can be used to emit structured log messages with a
 * specified event name, details, and log level.
 */
export function createEmitter(logger: Logger): (event: string, type?: Level) => void {
  return (event, type = 'debug') => {
    logger[type](event);
  };
}
