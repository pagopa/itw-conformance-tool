export const testCategoryFilters = {
  issuance: 'issuance.test.ts',
  presentation: 'presentation.test.ts',
  'wallet-instance': 'wallet-instance.test.ts',
  'wallet-provider': 'wallet-provider.test.ts'
} as const;

export type TestCategory = keyof typeof testCategoryFilters;

export const testCategories = Object.keys(testCategoryFilters) as TestCategory[];

export function isTestCategory(value: string): value is TestCategory {
  return Object.hasOwn(testCategoryFilters, value);
}
