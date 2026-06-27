/**
 * Pallas curve arithmetic — @noble/curves abstract weierstrass (optimized:
 * projective + wNAF, ~native speed: scalarMul ≈ 0.15ms vs 36ms naive-affine) with
 * the pure-TS pasta_curves-compatible compressed encoding layered on top.
 *
 *   Curve y² = x³ + 5 over Fp, group order |Fq|, generator G = (−1, 2).
 *   Compressed encoding (pasta GroupEncoding): 32-byte LE x, parity of y in bit 255,
 *   identity = all zeros. Verified byte-identical to pasta_curves.
 */
import { weierstrass } from '@noble/curves/abstract/weierstrass.js';
import { Field } from '@noble/curves/abstract/modular.js';
import { Fp, FP_MODULUS, FQ_MODULUS } from './field.js';

export const B = 5n;

/** Affine point; `null` is the identity (point at infinity). */
export type Point = { x: bigint; y: bigint } | null;

const NobleFp = Field(FP_MODULUS);
const NobleFn = Field(FQ_MODULUS);
const Pallas = weierstrass({
  p: FP_MODULUS,
  n: FQ_MODULUS,
  h: 1n,
  a: 0n,
  b: B,
  Gx: FP_MODULUS - 1n, // −1
  Gy: 2n,
  Fp: NobleFp,
  Fn: NobleFn,
});

/** Group generator G = (−1, 2). */
export const GENERATOR: Point = { x: Fp.neg(1n), y: 2n };

function toNoble(p: NonNullable<Point>) {
  return Pallas.fromAffine({ x: p.x, y: p.y });
}
function fromNoble(P: ReturnType<typeof Pallas.fromAffine>): Point {
  if (P.equals(Pallas.ZERO)) return null;
  const a = P.toAffine();
  return { x: a.x, y: a.y };
}

export function isIdentity(p: Point): boolean {
  return p === null;
}

export function isOnCurve(p: Point): boolean {
  if (p === null) return true;
  return Fp.square(p.y) === Fp.add(Fp.mul(Fp.square(p.x), p.x), B);
}

export function neg(p: Point): Point {
  return p === null ? null : { x: p.x, y: Fp.neg(p.y) };
}

export function double(p: Point): Point {
  return p === null ? null : fromNoble(toNoble(p).double());
}

export function add(p: Point, q: Point): Point {
  if (p === null) return q;
  if (q === null) return p;
  return fromNoble(toNoble(p).add(toNoble(q)));
}

/** Scalar multiplication `k·P` (k reduced into the scalar field; 0 → identity). */
export function scalarMul(k: bigint, p: Point): Point {
  if (p === null) return null;
  const kk = ((k % FQ_MODULUS) + FQ_MODULUS) % FQ_MODULUS;
  if (kk === 0n) return null;
  return fromNoble(toNoble(p).multiply(kk));
}

/** Compressed 32-byte encoding (pasta GroupEncoding). Identity → all zeros. */
export function toBytes(p: Point): Uint8Array {
  if (p === null) return new Uint8Array(32);
  const out = Fp.toBytes(p.x);
  if (p.y & 1n) out[31] |= 0x80;
  return out;
}

/** Decode a compressed point; recovers y via field sqrt (Tonelli-Shanks, p ≡ 1 mod 4). */
export function fromBytes(b: Uint8Array): Point {
  if (b.length !== 32) throw new Error('curve.fromBytes: expected 32 bytes');
  if (b.every((v) => v === 0)) return null;
  const buf = b.slice();
  const ySign = (buf[31] & 0x80) >> 7;
  buf[31] &= 0x7f;
  const x = Fp.fromBytes(buf);
  const y2 = Fp.add(Fp.mul(Fp.square(x), x), B);
  let y = NobleFp.sqrt(y2); // handles p ≡ 1 (mod 4)
  if (Fp.square(y) !== y2) throw new Error('curve.fromBytes: not on curve');
  if (Number(y & 1n) !== ySign) y = Fp.neg(y);
  return { x, y };
}
