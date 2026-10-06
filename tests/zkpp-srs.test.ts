// The commitment key the TS client derives must equal halo2 `Params::new(11)`
// (fixtures/srs-k11.bin, written by the Rust reference): every generator, its
// Lagrange basis and the blinding and inner-product generators.
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { Vesta } from "../src/curve.js";
import type { Srs } from "../src/halo2/keygen.js";
import { LocalPool } from "../src/halo2/kernel.js";
import { generateSrs, generateSrsOn, hashToVesta } from "../src/halo2/srs.js";
import { nodePool } from "./support/node-pool.js";

const srsBytes = new Uint8Array(
  readFileSync(new URL("./fixtures/srs-k11.bin", import.meta.url)),
);
const hex = (b: Uint8Array): string =>
  [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
const at = (i: number) => hex(srsBytes.subarray(4 + 32 * i, 4 + 32 * (i + 1)));

describe("SRS matches halo2 Params::new", () => {
  it("hashes the first generators like pasta_curves", () => {
    for (let i = 0; i < 4; i++) {
      const m = new Uint8Array(5);
      new DataView(m.buffer).setUint32(1, i, true);
      expect(hex(Vesta.toBytes(hashToVesta("Halo2-Parameters", m)))).toBe(
        at(i),
      );
    }
  });

  const expectReference = (srs: Srs) => {
    const n = 1 << 11;
    srs.g.forEach((p, i) => expect(hex(Vesta.toBytes(p))).toBe(at(i)));
    srs.gLagrange.forEach((p, i) =>
      expect(hex(Vesta.toBytes(p))).toBe(at(n + i)),
    );
    expect(hex(Vesta.toBytes(srs.w))).toBe(at(2 * n));
    expect(hex(Vesta.toBytes(srs.u))).toBe(at(2 * n + 1));
  };

  it("derives the whole key", () => {
    const t0 = performance.now();
    const srs = generateSrs(11);
    console.log(`SRS k=11: ${(performance.now() - t0).toFixed(0)} ms`);
    expectReference(srs);
  }, 600000);

  // The parallel derivation splits the inverse FFT into L strided
  // sub-transforms plus the remaining stages; any slip in the block order,
  // the sub-root or the stage twiddles changes the Lagrange basis. One lane
  // (no split), three (two blocks, a lane count that is not a power of two)
  // and eight (eight blocks) must all give the reference key, and the
  // progress must rise to 1 without going backwards.
  for (const lanes of [1, 3, 8]) {
    it(`derives the same key on ${lanes} lane(s)`, async () => {
      const pool = lanes === 1 ? new LocalPool() : nodePool(lanes);
      try {
        const seen: number[] = [];
        const t0 = performance.now();
        const srs = await generateSrsOn(pool, 11, (f) => seen.push(f));
        console.log(
          `SRS k=11 on ${lanes} lane(s): ${(performance.now() - t0).toFixed(0)} ms`,
        );
        expectReference(srs);
        expect(seen.at(-1)).toBe(1);
        seen.forEach((f, i) =>
          expect(f).toBeGreaterThanOrEqual(seen[i - 1] ?? 0),
        );
      } finally {
        pool.close();
      }
    }, 600000);
  }
});
