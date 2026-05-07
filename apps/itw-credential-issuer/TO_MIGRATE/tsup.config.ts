import { defineConfig } from "tsup";

export default defineConfig({
  clean: true,
  entry: ["./src/app/main.ts"],
  format: ["esm"],
  minify: false,
  platform: "node",
  sourcemap: true,
  splitting: false,
  target: "node22",
});
