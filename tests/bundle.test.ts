/**
 * An application bundles this package the way it is published: the built
 * entry plus the prover's workers beside it. A bundler finds a worker only
 * through `new Worker(new URL("<literal>", import.meta.url))`; anything else
 * fails the application's build or ships a page whose prover never starts.
 */
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { build as buildPackage } from "tsup";
import { build as bundleApp } from "vite";

const root = join(import.meta.dirname, "..");

describe("bundling the published package", () => {
  let dir: string;

  beforeAll(async () => {
    // Inside the checkout, so the package's dependencies resolve from its
    // node_modules as they would from the application's.
    const cache = join(root, "node_modules", ".cache");
    await mkdir(cache, { recursive: true });
    dir = await mkdtemp(join(cache, "opaque-bundle-"));
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("emits both prover workers into the application", async () => {
    const pkg = join(dir, "pkg");
    await buildPackage({
      config: join(root, "tsup.config.ts"),
      outDir: pkg,
      format: ["esm"],
      dts: false,
      sourcemap: false,
      silent: true,
    });

    const app = join(dir, "app");
    const entry = join(dir, "main.js");
    await writeFile(
      entry,
      // The whole public surface, so no export is shaken out of the bundle.
      `import * as opaque from ${JSON.stringify(join(pkg, "index.js"))};\n` +
        `globalThis.opaque = opaque;\n`,
    );
    await bundleApp({
      root: dir,
      logLevel: "silent",
      configFile: false,
      build: {
        outDir: app,
        emptyOutDir: true,
        rollupOptions: { input: entry },
      },
    });

    const emitted = await readdir(join(app, "assets"));
    expect(emitted.some((f) => f.startsWith("prover-worker"))).toBe(true);
    expect(emitted.some((f) => f.startsWith("lane-worker"))).toBe(true);
  }, 120_000);
});
