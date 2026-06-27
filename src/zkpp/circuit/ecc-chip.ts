/**
 * ECC variable-base mul — incomplete double-and-add witness (halo2_gadgets
 * ecc/chip/mul/incomplete.rs). Per scalar bit k (MSB-first):
 *   z   = 2·z + k                               (running-sum scalar reconstruction)
 *   yₚ  = k ? base.y : -base.y
 *   λ₁  = (y_a − yₚ)/(x_a − x_p)
 *   x_r = λ₁² − x_a − x_p
 *   λ₂  = 2·y_a/(x_a − x_r) − λ₁
 *   x_a' = λ₂² − x_a − x_r ;  y_a' = λ₂·(x_a − x_a') − y_a
 * (Fused double-and-add: doubles the accumulator and conditionally adds the base.)
 */
import { Fp } from '../field.js';

export interface EccRow {
  z: bigint;
  lambda1: bigint;
  lambda2: bigint;
  xa: bigint;
}

export interface IncompleteMul {
  rows: EccRow[];
  xa: bigint;
  ya: bigint;
  z: bigint;
}

export function incompleteDoubleAndAdd(
  xp: bigint,
  yp0: bigint,
  x0: bigint,
  y0: bigint,
  bits: number[],
  z0 = 0n,
): IncompleteMul {
  let xa = x0;
  let ya = y0;
  let z = z0;
  const rows: EccRow[] = [];
  for (const k of bits) {
    z = Fp.add(Fp.mul(2n, z), BigInt(k));
    const yp = k ? yp0 : Fp.sub(0n, yp0);
    const lambda1 = Fp.mul(Fp.sub(ya, yp), Fp.inv(Fp.sub(xa, xp)));
    const xr = Fp.sub(Fp.sub(Fp.square(lambda1), xa), xp);
    const lambda2 = Fp.sub(Fp.mul(Fp.mul(2n, ya), Fp.inv(Fp.sub(xa, xr))), lambda1);
    const xaNew = Fp.sub(Fp.sub(Fp.square(lambda2), xa), xr);
    ya = Fp.sub(Fp.mul(lambda2, Fp.sub(xa, xaNew)), ya);
    rows.push({ z, lambda1, lambda2, xa: xaNew });
    xa = xaNew;
  }
  return { rows, xa, ya, z };
}

import { Pallas, type Point } from '../curve.js';

export interface CompleteRow {
  z: bigint;
  x: bigint;
  y: bigint;
}

/**
 * ECC variable-base mul complete-addition tail (halo2_gadgets mul/complete.rs):
 * per low bit k, acc = [2]·acc + (k ? base : −base) using complete addition, with
 * z = 2·z + k. Complete addition handles the exceptional/identity cases.
 */
export function completeAddition(
  base: Point,
  x0: bigint,
  y0: bigint,
  bits: number[],
  z0: bigint,
): { rows: CompleteRow[]; acc: Point; z: bigint } {
  let acc: Point = { x: x0, y: y0 };
  let z = z0;
  const rows: CompleteRow[] = [];
  for (const k of bits) {
    z = Fp.add(Fp.mul(2n, z), BigInt(k));
    const u = k ? base : Pallas.neg(base);
    acc = Pallas.add(Pallas.double(acc), u);
    const a = acc as { x: bigint; y: bigint };
    rows.push({ z, x: a.x, y: a.y });
  }
  return { rows, acc, z };
}
