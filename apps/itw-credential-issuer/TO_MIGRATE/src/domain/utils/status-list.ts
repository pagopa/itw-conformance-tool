import { type BitsPerStatus, StatusList } from "@sd-jwt/jwt-status-list";

export const BITS: BitsPerStatus = 1;
export const LIST: number[] = [0, 0, 0, 0, 0];
export const STATUS_LIST_URI = (baseURL: string) => `${baseURL}/statuslist/1`;

export function createStatusList(
  list: number[],
  bits: BitsPerStatus,
): StatusList {
  return new StatusList(list, bits);
}
