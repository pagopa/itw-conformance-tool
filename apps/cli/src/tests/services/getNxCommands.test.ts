import { describe, it, expect } from 'vitest';

import { getNxCommands } from '../../services/getNxCommands.js';

import type { CLIFlags } from '../../types/types.js';

function makeFlags(overrides: Partial<CLIFlags> = {}): CLIFlags {
  return {
    issuer: false,
    rp: false,
    all: false,
    force: false,
    config: { value: false, path: '' },
    ...overrides
  };
}

describe('getNxCommands', () => {
  it('returns run-many for all services when --all is set', () => {
    expect(getNxCommands(makeFlags({ all: true }))).toEqual([
      'run-many',
      '-t',
      'serve',
      '-p',
      'itw-credential-issuer,itw-relying-party'
    ]);
  });

  it('returns run-many when both issuer and rp flags are set', () => {
    expect(getNxCommands(makeFlags({ issuer: true, rp: true }))).toEqual([
      'run-many',
      '-t',
      'serve',
      '-p',
      'itw-credential-issuer,itw-relying-party'
    ]);
  });

  it('returns run-many when no service flag is provided (default)', () => {
    expect(getNxCommands(makeFlags())).toEqual([
      'run-many',
      '-t',
      'serve',
      '-p',
      'itw-credential-issuer,itw-relying-party'
    ]);
  });

  it('returns issuer command when only --issuer is set', () => {
    expect(getNxCommands(makeFlags({ issuer: true }))).toEqual(['run', 'itw-credential-issuer:serve']);
  });

  it('returns rp command when only --rp is set', () => {
    expect(getNxCommands(makeFlags({ rp: true }))).toEqual(['run', 'itw-relying-party:serve']);
  });
});
