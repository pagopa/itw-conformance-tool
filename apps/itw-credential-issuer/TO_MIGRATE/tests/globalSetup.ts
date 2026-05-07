/* eslint-disable no-console */

import { readFile } from "node:fs/promises";
import path from "node:path";

/**
 * @see https://vitest.dev/config/globalsetup.html
 */
export default async function setup() {
  const localSettings = path.resolve(
    import.meta.dirname,
    "../local.settings.json",
  );

  try {
    const fileContent = await readFile(localSettings, "utf-8");
    const config = JSON.parse(fileContent).Values;

    for (const [key, value] of Object.entries(config)) {
      // Use a non-reserved name for the base URL to avoid conflicts with vitest internals
      if (key === "BASE_URL") {
        process.env["E2E_BASE_URL"] = String(value);
      } else {
        process.env[key] = String(value);
      }
    }
  } catch (error) {
    console.warn(`Error reading or parsing ${localSettings}:`, error);
  }
}
