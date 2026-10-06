// Build the browser bench of the TypeScript prover into a directory a static
// server can serve: `node bench/browser/build.mjs <outdir>`.
import { build } from "esbuild";
import { copyFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

const outdir = process.argv[2];
if (!outdir) throw new Error("usage: build.mjs <outdir>");
const here = new URL(".", import.meta.url).pathname;
const fixtures = new URL("../../tests/fixtures/", import.meta.url).pathname;

await mkdir(outdir, { recursive: true });
await build({
  // Flat output names: the package's host finds its workers next to itself.
  entryPoints: {
    main: join(here, "main.ts"),
    orchestrator: join(here, "orchestrator.ts"),
    lane: join(here, "lane.ts"),
    "prover-worker": join(here, "../../src/zkpp/prover-worker.ts"),
    "lane-worker": join(here, "../../src/zkpp/lane-worker.ts"),
  },
  bundle: true,
  format: "esm",
  target: "es2022",
  outdir,
  logLevel: "warning",
});
await copyFile(join(here, "index.html"), join(outdir, "index.html"));
for (const f of ["proof-vector.json", "proof-rng.bin"])
  await copyFile(join(fixtures, f), join(outdir, f));
console.log(`built into ${outdir}`);
