/**
 * Pallas curve arithmetic (pure TS, BigInt, affine) — model of `pasta_curves::pallas`.
 *   - Curve: y² = x³ + 5 over Fp (a = 0, b = 5)
 *   - Group order = |Fq| (scalar field)
 *   - Generator G = (−1, 2)   (since (−1)³ + 5 = 4 = 2²)
 *   - Compressed encoding (GroupEncoding): 32-byte little-endian x, with the
 *     parity (oddness) of y stored in bit 255 (MSB of byte 31). Identity = all zeros.
 *
 * Affine + per-step inversion: correctness-first, not fast.
 */
import { Fp } from './field.js';

export const B = 5n;

/** Affine point; `null` is the identity (point at infinity). */
export type Point = { x: bigint; y: bigint } | null;

/** Group generator G = (−1, 2). */
export const GENERATOR: Point = { x: Fp.neg(1n), y: 2n };

/** Is `p` the curve identity? */
export function isIdentity(p: Point): boolean {
  return p === null;
}

/** Check a point satisfies y² = x³ + 5. */
export function isOnCurve(p: Point): boolean {
  if (p === null) return true;
  const lhs = Fp.square(p.y);
  const rhs = Fp.add(Fp.mul(Fp.square(p.x), p.x), B);
  return lhs === rhs;
}

export function neg(p: Point): Point {
  return p === null ? null : { x: p.x, y: Fp.neg(p.y) };
}

export function double(p: Point): Point {
  if (p === null) return null;
  if (p.y === 0n) return null;
  // λ = 3x² / 2y   (a = 0)
  const lambda = Fp.mul(Fp.mul(3n, Fp.square(p.x)), Fp.inv(Fp.mul(2n, p.y)));
  const x3 = Fp.sub(Fp.square(lambda), Fp.mul(2n, p.x));
  const y3 = Fp.sub(Fp.mul(lambda, Fp.sub(p.x, x3)), p.y);
  return { x: x3, y: y3 };
}

export function add(p: Point, q: Point): Point {
  if (p === null) return q;
  if (q === null) return p;
  if (p.x === q.x) {
    if (p.y === q.y) return double(p);
    return null; // p = -q
  }
  // λ = (qy - py) / (qx - px)
  const lambda = Fp.mul(Fp.sub(q.y, p.y), Fp.inv(Fp.sub(q.x, p.x)));
  const x3 = Fp.sub(Fp.sub(Fp.square(lambda), p.x), q.x);
  const y3 = Fp.sub(Fp.mul(lambda, Fp.sub(p.x, x3)), p.y);
  return { x: x3, y: y3 };
}

/** Scalar multiplication `k·P` (double-and-add; `k` reduced into the scalar field by caller). */
export function scalarMul(k: bigint, p: Point): Point {
  let result: Point = null;
  let addend = p;
  let n = k;
  while (n > 0n) {
    if (n & 1n) result = add(result, addend);
    addend = double(addend);
    n >>= 1n;
  }
  return result;
}

/** Compressed 32-byte encoding (pasta_curves GroupEncoding). Identity → all zeros. */
export function toBytes(p: Point): Uint8Array {
  if (p === null) return new Uint8Array(32);
  const out = Fp.toBytes(p.x); // 32-byte LE x
  if (p.y & 1n) out[31] |= 0x80; // parity of y in bit 255
  return out;
}

/** Decode a compressed point; recovers y from x and the parity bit. */
export function fromBytes(b: Uint8Array): Point {
  if (b.length !== 32) throw new Error('curve.fromBytes: expected 32 bytes');
  if (b.every((v) => v === 0)) return null; // identity
  const buf = b.slice();
  const ySign = (buf[31] & 0x80) >> 7;
  buf[31] &= 0x7f;
  const x = Fp.fromBytes(buf);
  // y² = x³ + 5
  const y2 = Fp.add(Fp.mul(Fp.square(x), x), B);
  let y = Fp.pow(y2, (Fp.p + 1n) / 4n); // p ≡ 3 (mod 4) → sqrt = y2^((p+1)/4)
  if (Fp.square(y) !== y2) throw new Error('curve.fromBytes: not on curve');
  if (Number(y & 1n) !== ySign) y = Fp.neg(y);
  return { x, y };
}
