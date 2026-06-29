import { defineConfig } from 'vitest/config';
import { playwright } from '@vitest/browser-playwright';

// Browser-mode config: runs *.browser.test.ts in real Chromium (via Playwright),
// where Web Workers actually exist — so the worker pool runs in parallel rather
// than falling back to inline. Used to verify + measure the worker parallelism
// that the Node test environment cannot exercise.
export default defineConfig({
  test: {
    include: ['tests/**/*.browser.test.ts'],
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: 'chromium' }],
    },
  },
});
