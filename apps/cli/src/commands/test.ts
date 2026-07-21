import type { EmitLog } from '../types/types.js';

/** Blocks until SIGINT or SIGTERM is received.
 * Services must already be running via `itwct start --all`.
 * Conformance hooks on the RP record WP checks to SQLite on every real wallet request.
 * After stopping, use `itwct report:list` / `itwct report:create <uuid>`.
 *
 * @param _env - Unused; kept for signature consistency with other commands.
 * @param emitLog - Logger function for console output
 */
export async function test(_env: NodeJS.ProcessEnv, emitLog: EmitLog): Promise<void> {
  emitLog('Conformance test mode active. Make sure services are running via `itwct start --all`.', 'info');
  emitLog('Run wallet flows against the RP. Press Ctrl+C to stop.', 'info');

  await new Promise<void>((resolve) => {
    // A referenced timer is required to keep the Node.js event loop alive.
    // Signal listeners alone are not sufficient to prevent the process from exiting.
    const keepAlive = setInterval(() => {}, 1 << 30);

    const stop = (): void => {
      clearInterval(keepAlive);
      resolve();
    };

    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });

  emitLog('Test session ended. Run `itwct report:list` to view captured sessions.', 'info');
}
