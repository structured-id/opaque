import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";

// Browser-mode config: runs *.browser.test.ts in real Chromium (via Playwright)
// for what the Node environment lacks, such as IndexedDB.
export default defineConfig({
  // Cross-origin isolation, as on the pages that run a native kernel, so the
  // TS kernels are tested where SharedArrayBuffer exists too.
  server: {
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
  },
  // The test evaluator's imports beyond the sources' own; pre-bundled, so
  // Vite does not discover them mid-run and reload the page under a test.
  optimizeDeps: {
    include: [
      "@noble/curves/abstract/hash-to-curve.js",
      "@noble/hashes/sha2.js",
    ],
  },
  test: {
    include: ["tests/**/*.browser.test.ts"],
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: "chromium" }],
    },
  },
});
