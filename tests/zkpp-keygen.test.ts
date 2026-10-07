// Key generation of the TS circuit port against the Rust reference: the
// verifying key's pinned text (constraint system after selector
// compression, fixed and permutation commitments) must equal the Rust
// `format!("{:?}", vk.pinned())` for each shape (fixtures from the
// sid-pake-core `circuit_vectors` example), so the transcript
// representative, and with it every proof challenge, matches.
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { Vesta, type Point } from "../src/curve.js";
import { keygen, keygenWith, type Srs } from "../src/halo2/keygen.js";
import { CE_DEFAULT_POLICY } from "../src/zkpp/circuit.js";
import { zkppCircuit } from "../src/zkpp/zkpp-circuit.js";
import { nodePool } from "./support/node-pool.js";

const fixture = (name: string) =>
  new URL(`./fixtures/${name}`, import.meta.url);

function readSrs(): Srs {
  const bytes = readFileSync(fixture("srs-k11.bin"));
  const k = bytes.readUInt32LE(0);
  const n = 1 << k;
  let at = 4;
  const point = (): NonNullable<Point> => {
    const p = Vesta.fromBytes(new Uint8Array(bytes.subarray(at, at + 32)));
    at += 32;
    if (p === null) throw new Error("identity in the SRS");
    return p;
  };
  const g = Array.from({ length: n }, point);
  const gLagrange = Array.from({ length: n }, point);
  const w = point();
  const u = point();
  return { k, g, gLagrange, w, u };
}

/** The first differing character with some context on each side. */
function firstDifference(a: string, b: string): string {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  if (i === a.length && i === b.length) return "equal";
  return `at ${i}:\n  TS:   …${a.slice(Math.max(0, i - 160), i + 160)}\n  Rust: …${b.slice(Math.max(0, i - 160), i + 160)}`;
}

describe("ZKPP keygen matches the Rust reference", () => {
  const srs = readSrs();
  for (const domains of [1, 2]) {
    it(`pinned verifying key, CE policy, ${domains} domain(s)`, () => {
      const result = keygen(
        zkppCircuit({ policy: CE_DEFAULT_POLICY, historyDomains: domains }),
        srs,
      );
      const expected = readFileSync(
        fixture(`pinned-ce-${domains}.txt`),
        "utf8",
      );
      if (result.pinned !== expected)
        throw new Error(firstDifference(result.pinned, expected));
      expect(result.pinned).toBe(expected);
    }, 600000);
  }

  // The client commits the key's columns on its lanes: the pool's MSMs plus
  // the blind added after them must give the same verifying key, so a key
  // prepared in workers proves under the server's verifier.
  it("pinned verifying key with the commitments on 3 lanes", async () => {
    const pool = nodePool(3);
    try {
      await pool.init(srs);
      const result = await keygenWith(
        zkppCircuit({ policy: CE_DEFAULT_POLICY, historyDomains: 1 }),
        srs,
        (polys) => pool.msmMany(polys, "lagrange"),
      );
      const expected = readFileSync(fixture("pinned-ce-1.txt"), "utf8");
      if (result.pinned !== expected)
        throw new Error(firstDifference(result.pinned, expected));
      expect(result.pinned).toBe(expected);
    } finally {
      pool.close();
    }
  }, 600000);
});
