// The batched point arithmetic must give the same group elements as one
// scalar multiplication and addition at a time: the MSM on random and
// degenerate inputs (zero and top scalars, repeated and opposite points,
// sums that cancel), and the per-point multiplication and addition batches
// the IPA folding and the SRS use.
import { describe, it, expect } from "vitest";
import { Vesta, type Point } from "../src/curve.js";
import { FP_MODULUS } from "../src/field.js";

const N = FP_MODULUS;
let seed = 0x9e3779b97f4a7c15n;
const rand = (): bigint => {
  let v = 0n;
  for (let i = 0; i < 4; i++) {
    seed =
      (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    v = (v << 64n) | seed;
  }
  return v % N;
};
const G = Vesta.GENERATOR;
const pointOf = (k: bigint) => Vesta.scalarMul(k, G) as NonNullable<Point>;
const naive = (s: bigint[], p: NonNullable<Point>[]): Point =>
  s.reduce<Point>(
    (acc, k, i) => Vesta.add(acc, Vesta.scalarMul(k, p[i])),
    null,
  );

describe("batched MSM", () => {
  // The naive reference (one scalar multiplication per point, 513 points)
  // takes seconds of CPU; in the full suite it shares the cores with the
  // proving tests and outruns the default 5 s.
  it(
    "matches the naive sum on random inputs of many sizes",
    { timeout: 60_000 },
    () => {
      // 9 is the smallest size where a bucket pends several times in one pass
      for (const n of [1, 2, 3, 7, 9, 32, 100, 513]) {
        const s = Array.from({ length: n }, rand);
        const p = Array.from({ length: n }, () => pointOf(rand()));
        expect(Vesta.msm(s, p)).toEqual(naive(s, p));
      }
    },
  );

  it("handles zero, top and small scalars", () => {
    const p = Array.from({ length: 40 }, () => pointOf(rand()));
    const s = p.map((_, i) =>
      i % 4 === 0
        ? 0n
        : i % 4 === 1
          ? N - 1n
          : i % 4 === 2
            ? BigInt(i)
            : rand(),
    );
    expect(Vesta.msm(s, p)).toEqual(naive(s, p));
    expect(
      Vesta.msm(
        p.map(() => 0n),
        p,
      ),
    ).toBeNull();
  });

  it("handles repeated and opposite points and a cancelling sum", () => {
    const a = pointOf(rand());
    const p = [a, a, a, Vesta.neg(a) as NonNullable<Point>, a];
    const s = [rand(), rand(), 5n, 7n, rand()];
    expect(Vesta.msm(s, p)).toEqual(naive(s, p));
    // k·A + k·(−A) = identity
    const k = rand();
    expect(
      Vesta.msm([k, k], [a, Vesta.neg(a) as NonNullable<Point>]),
    ).toBeNull();
    // many copies of one point land in the same buckets
    const same = Array.from({ length: 300 }, () => a);
    const ss = same.map(() => rand());
    expect(Vesta.msm(ss, same)).toEqual(naive(ss, same));
  });
});

describe("batched per-point operations", () => {
  it("multiplies each point by its own or a shared scalar", () => {
    const p: Point[] = Array.from({ length: 50 }, () => pointOf(rand()));
    p[3] = null;
    const s = p.map((_, i) => (i === 5 ? 0n : i === 6 ? N - 1n : rand()));
    expect(Vesta.mulEach(s, p)).toEqual(
      p.map((q, i) => Vesta.scalarMul(s[i], q)),
    );
    const k = rand();
    expect(Vesta.mulEach(k, p)).toEqual(p.map((q) => Vesta.scalarMul(k, q)));
  });

  it("adds pointwise, including equal, opposite and identity pairs", () => {
    const a = pointOf(rand());
    const ps: Point[] = [a, a, null, a, pointOf(rand())];
    const qs: Point[] = [a, Vesta.neg(a), a, null, pointOf(rand())];
    expect(Vesta.addEach(ps, qs)).toEqual(
      ps.map((q, i) => Vesta.add(q, qs[i])),
    );
  });
});
