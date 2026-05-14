import { describe, expect, it } from 'vitest';

import { STATUS_LIST_BITS, STATUS_LIST_DEFAULT, STATUS_LIST_URI, createStatusList } from '../../utils/status-list.js';

describe('createStatusList', () => {
  it('creates a StatusList with the given parameters', () => {
    const statusList = createStatusList(STATUS_LIST_DEFAULT, STATUS_LIST_BITS);

    expect(statusList).toBeDefined();
    expect(statusList.compressStatusList()).toBeTruthy();
  });

  it('creates a compressed list', () => {
    const statusList = createStatusList([0, 0, 0, 0, 0], 1);
    const compressed = statusList.compressStatusList();

    expect(typeof compressed).toBe('string');
    expect(compressed.length).toBeGreaterThan(0);
  });
});

describe('STATUS_LIST_URI', () => {
  it('returns the correct URI for a given baseURL', () => {
    expect(STATUS_LIST_URI('https://example.com')).toBe('https://example.com/statuslist/1');
  });
});
