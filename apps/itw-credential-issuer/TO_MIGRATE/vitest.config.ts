import * as path from "node:path";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  test: {
    environment: "node",
    exclude: [...configDefaults.exclude, "**/*.e2e.spec.ts"],
    globalSetup: ["./tests/globalSetup.ts"],
  },
});
