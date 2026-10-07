// The stored key and its use by the client. A visit that finds the key must
// rebuild exactly the key a fresh derivation gives (same verifying key, so the
// server's verifier accepts its proofs) without deriving anything; anything
// damaged, foreign or unreadable must be derived again rather than used.
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { Vesta, type Point } from "../src/curve.js";
import { FQ_MODULUS } from "../src/field.js";
import { keygenColumns, type Srs } from "../src/halo2/keygen.js";
import { LocalPool, type Basis } from "../src/halo2/kernel.js";
import { CE_DEFAULT_POLICY } from "../src/zkpp/circuit.js";
import { zkppCircuit } from "../src/zkpp/zkpp-circuit.js";
import {
  columnsDigest,
  decodeCommitments,
  decodeSrs,
  encodeCommitments,
  encodeSrs,
} from "../src/zkpp/key-cache.js";
import { MemoryKeyStore, type KeyStore } from "../src/zkpp/key-store.js";
import { ProverCore } from "../src/zkpp/prover-core.js";

function readSrs(): Srs {
  const bytes = readFileSync(
    new URL("./fixtures/srs-k11.bin", import.meta.url),
  );
  const n = 1 << bytes.readUInt32LE(0);
  let at = 4;
  const point = () => {
    const p = Vesta.fromBytes(new Uint8Array(bytes.subarray(at, at + 32)));
    at += 32;
    return p as NonNullable<Point>;
  };
  const g = Array.from({ length: n }, point);
  const gLagrange = Array.from({ length: n }, point);
  return { k: 11, g, gLagrange, w: point(), u: point() };
}

const srs = readSrs();
const hex = (p: NonNullable<Point>) =>
  [...Vesta.toBytes(p)].map((v) => v.toString(16).padStart(2, "0")).join("");

/** A pool that counts the work it is given. */
class CountingPool extends LocalPool {
  msms = 0;
  hashes = 0;
  async msmMany(polys: bigint[][], basis: Basis): Promise<Point[]> {
    this.msms += polys.length;
    return super.msmMany(polys, basis);
  }
  async generators(r: [number, number][], onDone?: () => void) {
    this.hashes += r.length;
    return super.generators(r, onDone);
  }
}

describe("stored commitment key", () => {
  it("round-trips point for point", () => {
    const back = decodeSrs(encodeSrs(srs), 11);
    expect(back).not.toBeNull();
    expect(back!.g.map(hex)).toEqual(srs.g.map(hex));
    expect(back!.gLagrange.map(hex)).toEqual(srs.gLagrange.map(hex));
    expect(hex(back!.w)).toBe(hex(srs.w));
    expect(hex(back!.u)).toBe(hex(srs.u));
  });

  it("is refused when truncated, for another k, off the curve or non-canonical", () => {
    const bytes = encodeSrs(srs);
    expect(decodeSrs(bytes.slice(0, -1), 11)).toBeNull();
    expect(decodeSrs(bytes, 10)).toBeNull();
    const off = bytes.slice();
    off[off.length - 1] ^= 1; // u's y no longer satisfies the curve equation
    expect(decodeSrs(off, 11)).toBeNull();
    // x + q satisfies y² = x³ + 5 mod q but is not the canonical encoding.
    const shifted = bytes.slice();
    const at = 3 + 4; // header, count, then the first point's x
    let x = 0n;
    for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(shifted[at + i]);
    const big = x + FQ_MODULUS;
    if (big < 1n << 256n) {
      for (let i = 0; i < 32; i++)
        shifted[at + i] = Number((big >> BigInt(8 * i)) & 0xffn);
      expect(decodeSrs(shifted, 11)).toBeNull();
    }
  });
});

describe("stored column commitments", () => {
  const columns = keygenColumns(
    zkppCircuit({ policy: CE_DEFAULT_POLICY, historyDomains: 1 }),
    11,
  );
  const digest = columnsDigest(columns);

  it("belong to exactly the columns they were made for", () => {
    const other = columnsDigest(
      keygenColumns(
        zkppCircuit({ policy: CE_DEFAULT_POLICY, historyDomains: 2 }),
        11,
      ),
    );
    expect(other).not.toEqual(digest);
    const points = [srs.w, srs.u];
    const bytes = encodeCommitments(digest, points);
    expect(decodeCommitments(bytes, digest, 2)?.map(hex)).toEqual(
      points.map(hex),
    );
    expect(decodeCommitments(bytes, other, 2)).toBeNull();
    expect(decodeCommitments(bytes, digest, 3)).toBeNull();
  });
});

describe("the client's key across visits", () => {
  it("a second visit rebuilds the same key from the store, deriving nothing", async () => {
    const store = new MemoryKeyStore();
    const first = new CountingPool();
    const pk1 = await new ProverCore(first, undefined, store).prepare(1, 1);
    expect(first.hashes).toBeGreaterThan(0);
    expect(first.msms).toBeGreaterThan(0);

    const second = new CountingPool();
    const seen: string[] = [];
    const pk2 = await new ProverCore(second, undefined, store).prepare(
      1,
      1,
      (stage, f) => seen.push(`${stage}:${f}`),
    );
    expect(second.hashes).toBe(0);
    expect(second.msms).toBe(0);
    expect(pk2.id).toBe(pk1.id);
    expect(pk2.keygen.pinned).toBe(pk1.keygen.pinned);
    expect(seen).toContain("srs:1");
    expect(seen).toContain("keygen:1");
  }, 600000);

  it("a damaged entry is derived again and replaced", async () => {
    const store = new MemoryKeyStore();
    const pk1 = await new ProverCore(new LocalPool(), undefined, store).prepare(
      1,
      1,
    );
    const entry = (await store.get("key:1:1")) as Uint8Array;
    const damaged = entry.slice();
    damaged[damaged.length - 1] ^= 1;
    await store.put("key:1:1", damaged);

    const pool = new CountingPool();
    const pk2 = await new ProverCore(pool, undefined, store).prepare(1, 1);
    expect(pool.msms).toBeGreaterThan(0);
    expect(pk2.id).toBe(pk1.id);
    expect(await store.get("key:1:1")).toEqual(entry);
  }, 600000);

  it("a failing store only costs the derivation", async () => {
    const failing: KeyStore = {
      get: async () => {
        throw new Error("blocked");
      },
      put: async () => {
        throw new Error("quota");
      },
      touch: async () => {
        throw new Error("blocked");
      },
      delete: async () => {
        throw new Error("blocked");
      },
      list: async () => {
        throw new Error("blocked");
      },
    };
    const pk = await new ProverCore(
      new LocalPool(),
      undefined,
      failing,
    ).prepare(1, 1);
    expect(pk.id).toMatch(/^[0-9a-f]+$/);
  }, 600000);

  it("removes shapes unused for 90 days, keeping the commitment key", async () => {
    const store = new MemoryKeyStore();
    await store.put("key:7:3", new Uint8Array([1]));
    await store.put("srs:11", new Uint8Array([2]));
    const old = Date.now() - 91 * 24 * 3600 * 1000;
    for (const e of (
      store as unknown as { entries: Map<string, { usedAt: number }> }
    ).entries.values())
      e.usedAt = old;
    await new ProverCore(new LocalPool(), undefined, store).prepare(1, 1);
    // Pruning runs after preparation, without the caller waiting for it.
    await new Promise((r) => setTimeout(r, 50));
    const names = (await store.list()).map((e) => e.name).sort();
    expect(names).toEqual(["key:1:1", "srs:11"]);
  }, 600000);
});
