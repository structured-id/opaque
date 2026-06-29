/**
 * Pasta curves (Pallas + Vesta) — @noble/curves abstract weierstrass (projective +
 * wNAF, ~native) with the pure-TS pasta_curves-compatible compressed encoding.
 *
 *   y² = x³ + 5, generator (−1, 2), order = the sister field.
 *   Pallas: base Fp, scalar Fq.   Vesta: base Fq, scalar Fp (the IPA commitment curve).
 *   Encoding: 32-byte LE x, parity of y in bit 255, identity = all zeros.
 *
 * Top-level exports are the Pallas instance (binding etc.); `Pallas`/`Vesta` give both.
 */
import { weierstrass } from "@noble/curves/abstract/weierstrass.js";
import { pippenger } from "@noble/curves/abstract/curve.js";
import { Field as NobleField } from "@noble/curves/abstract/modular.js";
import { Field, FP_MODULUS, FQ_MODULUS } from "./field.js";

export const B = 5n;

/** Affine point; `null` is the identity. */
export type Point = { x: bigint; y: bigint } | null;

export interface Curve {
  readonly GENERATOR: { x: bigint; y: bigint };
  readonly MODULUS: bigint;
  readonly ORDER: bigint;
  scalarMul(k: bigint, p: Point): Point;
  add(p: Point, q: Point): Point;
  double(p: Point): Point;
  neg(p: Point): Point;
  isIdentity(p: Point): boolean;
  isOnCurve(p: Point): boolean;
  toBytes(p: Point): Uint8Array;
  fromBytes(b: Uint8Array): Point;
  /** Multi-scalar multiplication Σ kᵢ·Pᵢ. */
  msm(scalars: bigint[], points: { x: bigint; y: bigint }[]): Point;
}

function makeCurve(P: bigint, N: bigint, Gx: bigint, Gy: bigint): Curve {
  const F = new Field(P); // base field: LE encoding + on-curve check
  const NFp = NobleField(P);
  const NFn = NobleField(N);
  const C = weierstrass(
    { p: P, n: N, h: 1n, a: 0n, b: B, Gx, Gy },
    { Fp: NFp, Fn: NFn },
  );

  const GENERATOR = { x: F.mod(Gx), y: F.mod(Gy) };
  const toNoble = (p: { x: bigint; y: bigint }) =>
    C.fromAffine({ x: p.x, y: p.y });
  const fromNoble = (Q: ReturnType<typeof C.fromAffine>): Point => {
    if (Q.equals(C.ZERO)) return null;
    const a = Q.toAffine();
    return { x: a.x, y: a.y };
  };

  const neg = (p: Point): Point =>
    p === null ? null : { x: p.x, y: F.neg(p.y) };
  const double = (p: Point): Point =>
    p === null ? null : fromNoble(toNoble(p).double());
  const add = (p: Point, q: Point): Point => {
    if (p === null) return q;
    if (q === null) return p;
    return fromNoble(toNoble(p).add(toNoble(q)));
  };
  const scalarMul = (k: bigint, p: Point): Point => {
    if (p === null) return null;
    const kk = ((k % N) + N) % N;
    if (kk === 0n) return null;
    return fromNoble(toNoble(p).multiply(kk));
  };
  // Cache the affine->projective conversion of fixed base sets (SRS g/g_lagrange
  // are reused across ~80 MSMs): convert + validate once per array, then index.
  const baseCache = new WeakMap<object, ReturnType<typeof C.fromAffine>[]>();
  const msm = (
    scalars: bigint[],
    points: { x: bigint; y: bigint }[],
  ): Point => {
    let nobleAll = baseCache.get(points);
    if (!nobleAll) {
      nobleAll = points.map(toNoble);
      baseCache.set(points, nobleAll);
    }
    const pts: ReturnType<typeof C.fromAffine>[] = [];
    const scs: bigint[] = [];
    for (let i = 0; i < scalars.length; i++) {
      const s = ((scalars[i] % N) + N) % N;
      if (s !== 0n) {
        pts.push(nobleAll[i]);
        scs.push(s);
      }
    }
    if (pts.length === 0) return null;
    return fromNoble(pippenger(C, pts, scs));
  };
  const isOnCurve = (p: Point): boolean =>
    p === null ? true : F.square(p.y) === F.add(F.mul(F.square(p.x), p.x), B);
  const toBytes = (p: Point): Uint8Array => {
    if (p === null) return new Uint8Array(32);
    const out = F.toBytes(p.x);
    if (p.y & 1n) out[31] |= 0x80;
    return out;
  };
  const fromBytes = (b: Uint8Array): Point => {
    if (b.length !== 32) throw new Error("curve.fromBytes: expected 32 bytes");
    if (b.every((v) => v === 0)) return null;
    const buf = b.slice();
    const ySign = (buf[31] & 0x80) >> 7;
    buf[31] &= 0x7f;
    const x = F.fromBytes(buf);
    const y2 = F.add(F.mul(F.square(x), x), B);
    let y = NFp.sqrt(y2); // p ≡ 1 (mod 4): Tonelli-Shanks
    if (F.square(y) !== y2) throw new Error("curve.fromBytes: not on curve");
    if (Number(y & 1n) !== ySign) y = F.neg(y);
    return { x, y };
  };

  return {
    GENERATOR,
    MODULUS: P,
    ORDER: N,
    scalarMul,
    add,
    double,
    neg,
    isIdentity: (p) => p === null,
    isOnCurve,
    toBytes,
    fromBytes,
    msm,
  };
}

/** Pallas: base Fp, scalar Fq. Generator (−1, 2). */
export const Pallas = makeCurve(FP_MODULUS, FQ_MODULUS, FP_MODULUS - 1n, 2n);
/** Vesta: base Fq, scalar Fp (IPA commitment curve). Generator (−1, 2). */
export const Vesta = makeCurve(FQ_MODULUS, FP_MODULUS, FQ_MODULUS - 1n, 2n);

// Default top-level exports = Pallas (binding, HashToCurve, existing callers).
export const GENERATOR: Point = Pallas.GENERATOR;
export const scalarMul = Pallas.scalarMul;
export const add = Pallas.add;
export const double = Pallas.double;
export const neg = Pallas.neg;
export const isIdentity = Pallas.isIdentity;
export const isOnCurve = Pallas.isOnCurve;
export const toBytes = Pallas.toBytes;
export const fromBytes = Pallas.fromBytes;
