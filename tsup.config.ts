import { defineConfig } from "tsup";

export default defineConfig({
  // The prover's workers ship as their own entries next to index.js, where
  // prover-host.ts resolves them by `new URL("./<name>.js", import.meta.url)`.
  entry: {
    index: "src/index.ts",
    "prover-worker": "src/zkpp/prover-worker.ts",
    "lane-worker": "src/zkpp/lane-worker.ts",
  },
  format: ["cjs", "esm"],
  dts: { entry: { index: "src/index.ts" } },
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  shims: true,
  target: "es2024",
});
