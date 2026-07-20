import { spawn } from 'node:child_process';

import type { ChildProcessWithoutNullStreams } from 'node:child_process';

export type ClipboardCommand = readonly [command: string, args: string[]];

export function getClipboardCommands(platform: NodeJS.Platform = process.platform): ClipboardCommand[] {
  if (platform === 'darwin') return [['pbcopy', []]];
  if (platform === 'win32') return [['clip', []]];
  if (platform === 'linux') {
    return [
      ['wl-copy', []],
      ['xclip', ['-selection', 'clipboard']],
      ['xsel', ['--clipboard', '--input']]
    ];
  }

  return [];
}

function writeToClipboard(command: ClipboardCommand, text: string): Promise<boolean> {
  return new Promise((resolve) => {
    const [executable, args] = command;
    let child: ChildProcessWithoutNullStreams;

    try {
      child = spawn(executable, args, { stdio: 'pipe' });
    } catch {
      resolve(false);
      return;
    }

    child.once('error', () => resolve(false));
    child.once('close', (code) => resolve(code === 0));
    child.stdin.end(text);
  });
}

/** Copies text using the native clipboard command for the current platform.
 * Returns false when the terminal host does not provide a supported command. */
export async function copyTextToClipboard(
  text: string,
  platform: NodeJS.Platform = process.platform
): Promise<boolean> {
  for (const command of getClipboardCommands(platform)) {
    if (await writeToClipboard(command, text)) return true;
  }

  return false;
}
