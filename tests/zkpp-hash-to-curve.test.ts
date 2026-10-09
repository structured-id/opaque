// Native HashToCurve (gadget C) interop vs Rust gadget_c::hash_to_curve_outside.
// Vector from the sid-pake-core `circuit_vectors` example (hash-to-curve.json).
import { describe, it, expect } from "vitest";
import { Fp } from "../src/field.js";
import { hashToCurveOutside } from "../src/hash-to-curve.js";
import v from "./fixtures/hash-to-curve.json";

const hex = (b: Uint8Array) =>
  [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const fe = (value: bigint) => hex(Fp.toBytes(value));
const te = new TextEncoder();

describe("Native HashToCurve (gadget C) — Rust interop", () => {
  const r = hashToCurveOutside(te.encode(v.password));

  it("u = Poseidon(password) matches Rust", () => {
    expect(fe(r.u)).toBe(v.u);
  });

  it("offset matches Rust", () => {
    expect(r.offset).toBe(BigInt(v.offset));
  });

  it("H_p.x matches Rust", () => {
    expect(fe(r.point.x)).toBe(v.hpx);
  });

  // The even root (sgn0 of RFC 9380 §4.1), the suite's prescribed sign.
  it("H_p.y is the even root, as in Rust", () => {
    expect(fe(r.point.y)).toBe(v.hpy);
    expect(r.point.y % 2n).toBe(0n);
  });

  it("H_p is on the curve (y² = x³ + 5)", () => {
    expect(Fp.square(r.point.y)).toBe(
      Fp.add(Fp.mul(Fp.square(r.point.x), r.point.x), 5n),
    );
  });
});
