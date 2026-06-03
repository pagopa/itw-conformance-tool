import { describe, it, expect } from 'vitest';

import { getNxCommands } from '../../services/getNxCommands.js';

import type { CLIFlags } from '../../types/types.js';

// Helper function to create CLIFlags with defaults, allowing overrides for specific tests
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

const ISSUER_PROCESS = {
  prefix: 'itw-credential-issuer',
  nxArgs: ['run', 'itw-credential-issuer:serve']
};

const RP_PROCESS = {
  prefix: 'itw-relying-party',
  nxArgs: ['run', 'itw-relying-party:serve']
};

describe('getNxCommands', () => {
  it('returns both services when --all is set', () => {
    expect(getNxCommands(makeFlags({ all: true }))).toEqual([ISSUER_PROCESS, RP_PROCESS]);
  });

  it('returns both services when both issuer and rp flags are set', () => {
    expect(getNxCommands(makeFlags({ issuer: true, rp: true }))).toEqual([ISSUER_PROCESS, RP_PROCESS]);
  });

  it('returns both services when no service flag is provided (default)', () => {
    expect(getNxCommands(makeFlags())).toEqual([ISSUER_PROCESS, RP_PROCESS]);
  });

  it('returns only issuer when --issuer is set', () => {
    expect(getNxCommands(makeFlags({ issuer: true }))).toEqual([ISSUER_PROCESS]);
  });

  it('returns only rp when --rp is set', () => {
    expect(getNxCommands(makeFlags({ rp: true }))).toEqual([RP_PROCESS]);
  });
});
