/**
 * Native HashToCurve for gadget C (OPAQUE binder): H_p = HashToCurve(password).
 * Byte-identical to Rust `gadget_c::hash_to_curve_outside`:
 *   u = Poseidon(bytes_to_field_elements(password))   (hash chain)
 *   smallest offset i ∈ [0,256): x = u + i with x³+5 a QR; y = sqrt(x³+5)
 *   H_p = (x, y)
 *
 * The binding then uses M = blind·H_p and Com = H_p + r·G2, so H_p MUST match the
 * Rust point exactly (including the sqrt root convention).
 */
import { Field as NobleField } from '@noble/curves/abstract/modular.js';
import { Fp, FP_MODULUS } from './field.js';
import { bytesToFieldElements, hashChain } from './poseidon.js';
import type { Point } from './curve.js';

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

export function hashToCurveOutside(password: Uint8Array): HashToCurveResult {
  const u = hashChain(bytesToFieldElements(password));
  for (let i = 0n; i < 256n; i++) {
    const x = Fp.add(u, i);
    const x3b = Fp.add(Fp.mul(Fp.square(x), x), B);
    if (isSquare(x3b)) {
      const y = NFp.sqrt(x3b);
      return { point: { x, y }, u, offset: i };
    }
  }
  throw new Error('hashToCurve: no valid point in 256 tries');
}
