// The coset-class split must reproduce the extended-domain transforms it
// replaces: a class evaluation is every Q-th value of coeffToExtended, and
// interpolating all classes then combining them gives extendedToCoeff's
// coefficients (all Q·n of them, and the truncated prefix).
import { describe, it, expect } from "vitest";
import { Fp } from "../src/field.js";
import { coeffToExtended, extendedToCoeff } from "../src/domain.js";
import { CosetClass, combineClasses } from "../src/halo2/quotient.js";

let seed = 99n;
const fe = (): bigint => {
  seed =
    (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
  return Fp.mod(seed * seed * seed * seed + seed);
};

const K = 4;
const EXT_K = 6;
const N = 1 << K;
const Q = 1 << (EXT_K - K);

describe("coset classes", () => {
  it("evaluate a polynomial on every Q-th extended row", () => {
    const poly = Array.from({ length: N }, fe);
    const ext = coeffToExtended(poly, EXT_K);
    for (let r = 0; r < Q; r++) {
      const values = new CosetClass(r, K, EXT_K).evaluate(poly);
      values.forEach((v, q) => expect(v).toBe(ext[r + Q * q]));
    }
  });

  it("interpolate and combine back to the extended coefficients", () => {
    const values = Array.from({ length: Q * N }, fe);
    const ws = Array.from({ length: Q }, (_, r) =>
      new CosetClass(r, K, EXT_K).interpolate(
        Array.from({ length: N }, (_, q) => values[r + Q * q]),
      ),
    );
    expect(combineClasses(ws, K, Q)).toEqual(
      extendedToCoeff(values, K, EXT_K, Q),
    );
    expect(combineClasses(ws, K, 3)).toEqual(
      extendedToCoeff(values, K, EXT_K, 3),
    );
  });
});
