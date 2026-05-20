import { describe, expect, it } from 'vitest';

import { parseIni } from '../config.js';

describe('parseIni - Prototype Pollution Prevention', () => {
  it('should not pollute Object.prototype with __proto__ key', () => {
    const ini = '[rp]\n__proto__=polluted\nhost=localhost';
    const result = parseIni(ini);

    expect(result.rp).toBeDefined();
    expect(result.rp.__proto__).toBeUndefined();
    expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('should not pollute Object.prototype with constructor key', () => {
    const ini = '[rp]\nconstructor=polluted\nhost=localhost';
    const result = parseIni(ini);

    expect(result.rp).toBeDefined();
    expect(result.rp.constructor).toBeUndefined();
  });

  it('should not pollute Object.prototype with prototype key', () => {
    const ini = '[rp]\nprototype=polluted\nhost=localhost';
    const result = parseIni(ini);

    expect(result.rp).toBeDefined();
    expect(result.rp.prototype).toBeUndefined();
  });

  it('should parse normal keys correctly', () => {
    const ini = '[rp]\nhost=localhost\nport=8080';
    const result = parseIni(ini);

    expect(result.rp).toBeDefined();
    expect(result.rp.host).toBe('localhost');
    expect(result.rp.port).toBe('8080');
  });
});
