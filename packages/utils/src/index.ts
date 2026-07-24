export { readPackageVersion, resolveRootPackageJsonPath } from './package-json.js';
export { normalizeUrl, trimTrailingSlashes } from './url.js';
export {
  isTestCategory,
  testCategories,
  testCategoryByFileName,
  testCategoryNames,
  type TestCategory
} from './test-categories.js';
export { toFastifyJsonSchema } from './json-schema.js';
export { toResult } from './result.js';
