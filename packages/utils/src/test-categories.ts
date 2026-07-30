export const testCategories = {
  'wallet-provider': {
    fileName: 'wallet-provider.test.ts',
    title: 'Test Cases for Wallet Provider Backend'
  },
  'wallet-instance': {
    fileName: 'wallet-instance.test.ts',
    title: 'Test Cases for Wallet Instance'
  },
  issuance: {
    fileName: 'issuance.test.ts',
    title: 'Test Cases for Issuance Phase'
  },
  presentation: {
    fileName: 'presentation.test.ts',
    title: 'Test Cases for Presentation Phase'
  }
} as const;

export type TestCategory = keyof typeof testCategories;

export const testCategoryNames = Object.keys(testCategories) as TestCategory[];

export function isTestCategory(value: string): value is TestCategory {
  return Object.hasOwn(testCategories, value);
}

export const testCategoryByFileName = Object.fromEntries(
  Object.values(testCategories).map((category) => [category.fileName, category])
) as Record<(typeof testCategories)[TestCategory]['fileName'], (typeof testCategories)[TestCategory]>;
