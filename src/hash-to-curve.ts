/**
 * Native HashToCurve for gadget C (OPAQUE binder): H_p = HashToCurve(password).
 * Byte-identical to Rust `gadget_c::hash_to_curve_outside`:
 *   u = Poseidon(bytes_to_field_elements(password))   (hash chain)
 *   smallest offset i ∈ [0,256): x = u + i with x³+5 a QR; y = the even root
 *   H_p = (x, y)
 *
 * The binding then uses M = blind·H_p and Com = H_p + r·G2, so H_p MUST match the
 * Rust point exactly.
 */
import { Field as NobleField } from "@noble/curves/abstract/modular.js";
import { Fp, FP_MODULUS } from "./field.js";
import { bytesToFieldElements, hashChain } from "./poseidon.js";
import type { Point } from "./curve.js";

const NFp = NobleField(FP_MODULUS);
const B = 5n;

/** Euler's criterion: a is a non-zero square iff a^((p-1)/2) == 1. */
function isSquare(a: bigint): boolean {
  if (a === 0n) return true;
  return Fp.pow(a, (FP_MODULUS - 1n) / 2n) === 1n;
}

export interface HashToCurveResult {
  point: NonNullable<Point>;
  u: bigint;
  offset: bigint;
}

/**
 * Every one of the 256 offsets is tested and the first square is kept, as the
 * reference does, so the number of tries does not depend on Poseidon(password)
 * (RFC 9380 §10.1).
 */
export function hashToCurveOutside(password: Uint8Array): HashToCurveResult {
  const u = hashChain(bytesToFieldElements(password));
  let found: HashToCurveResult | null = null;
  for (let i = 0n; i < 256n; i++) {
    const x = Fp.add(u, i);
    const x3b = Fp.add(Fp.mul(Fp.square(x), x), B);
    const square = isSquare(x3b);
    if (square && found === null)
      found = { point: { x, y: NFp.sqrt(x3b) }, u, offset: i };
  }
  if (found === null)
    throw new Error("hashToCurve: no valid point in 256 tries");
  // Prescribed sign: the even root (sgn0 of RFC 9380 §4.1), as the history
  // mapping takes, so the root is a rule and not one sqrt's choice.
  const y = found.point.y;
  if (y % 2n === 1n) found.point = { x: found.point.x, y: Fp.neg(y) };
  return found;
}
