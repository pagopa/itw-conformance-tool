import { type BitsPerStatus, StatusList } from '@sd-jwt/jwt-status-list';

export const STATUS_LIST_BITS: BitsPerStatus = 1;
export const STATUS_LIST_DEFAULT: number[] = [0, 0, 0, 0, 0];
export const STATUS_LIST_TESTED_CREDENTIAL_INDEX = 1;

export const STATUS_LIST_URI = (baseURL: string): string => `${baseURL}/statuslist/1`;

export function createStatusList(list: number[], bits: BitsPerStatus): StatusList {
  return new StatusList(list, bits);
}
