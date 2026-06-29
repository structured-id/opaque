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
import { Fp } from "../field.js";

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
    const lambda2 = Fp.sub(
      Fp.mul(Fp.mul(2n, ya), Fp.inv(Fp.sub(xa, xr))),
      lambda1,
    );
    const xaNew = Fp.sub(Fp.sub(Fp.square(lambda2), xa), xr);
    ya = Fp.sub(Fp.mul(lambda2, Fp.sub(xa, xaNew)), ya);
    rows.push({ z, lambda1, lambda2, xa: xaNew });
    xa = xaNew;
  }
  return { rows, xa, ya, z };
}

import { Pallas, type Point } from "../curve.js";

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

/** t_q where the Pallas scalar field F_q = 2²⁵⁴ + t_q. */
export const T_Q = 45560315531506369815346746415080538113n;

/**
 * Scalar decomposition for variable-base mul (halo2_gadgets decompose_for_scalar_mul):
 * k = scalar + t_q (unreduced), returned as 255 big-endian (MSB-first) bits.
 */
export function decomposeForScalarMul(scalar: bigint): number[] {
  const k = scalar + T_Q;
  return Array.from({ length: 255 }, (_, i) =>
    Number((k >> BigInt(254 - i)) & 1n),
  );
}

/**
 * Full variable-base scalar mul (halo2_gadgets mul.rs assign): decompose k = scalar
 * + t_q, init acc = [2]·base, hi incomplete (125) → lo incomplete (126) → complete
 * (3) → process_lsb (result = acc + (k_0 ? 0 : −base)). Returns [scalar]·base.
 */
export function variableBaseMul(scalar: bigint, base: Point): Point {
  const b = base as { x: bigint; y: bigint };
  const bits = decomposeForScalarMul(scalar);
  const init = Pallas.double(base) as { x: bigint; y: bigint }; // [2]·base
  const hi = incompleteDoubleAndAdd(
    b.x,
    b.y,
    init.x,
    init.y,
    bits.slice(0, 125),
    0n,
  );
  const lo = incompleteDoubleAndAdd(
    b.x,
    b.y,
    hi.xa,
    hi.ya,
    bits.slice(125, 251),
    hi.z,
  );
  const comp = completeAddition(base, lo.xa, lo.ya, bits.slice(251, 254), lo.z);
  const lsb = bits[254];
  return lsb ? comp.acc : Pallas.add(comp.acc, Pallas.neg(base));
}

/**
 * Fixed-base mul scalar decomposition (halo2_gadgets mul_fixed RunningSumConfig):
 * the scalar split into `numWindows` little-endian FIXED_BASE_WINDOW_SIZE-bit
 * windows (H = 2^3 = 8). window_i = (z >> 3i) & 7.
 */
export function fixedBaseWindows(scalar: bigint, numWindows = 85): number[] {
  const windows: number[] = [];
  let z = scalar;
  for (let i = 0; i < numWindows; i++) {
    windows.push(Number(z & 7n));
    z >>= 3n;
  }
  return windows;
}

import { FQ_MODULUS } from "../field.js";
import { G2 as G2_POINT } from "../binding.js";
import { G2_U } from "./g2-tables.js";

/**
 * Per-window magnitude-check values `u` for halo2_gadgets fixed-base mul (binding
 * region column 27): the gate checks u^2 = y_p + z with a fixed per-window z
 * (halo2's find_zs_and_us). The exact pasta Fp roots are baked into the gadget as
 * compile-time constants, so we port them verbatim from the generated G2 table
 * rather than recompute sqrt (whose root-sign convention differs from @noble) —
 * this guarantees a byte-exact witness. `u[window][digit]`.
 */
export function fixedBaseUs(numWindows = 85): bigint[][] {
  return G2_U.slice(0, numWindows);
}

const H_BASE = 8n; // 2^FIXED_BASE_WINDOW_SIZE
const FBWS = 3n;

/**
 * Fixed-base mul window table (halo2_gadgets compute_window_table) for base G2:
 *   table[w][k] = [(k+2)·8^w]·G2          for w < numWindows-1
 *   table[last][k] = [k·8^last − sum]·G2  where sum = Σ_{j<last} 2^(3j+1)
 * The per-window "+2" offsets exactly cancel the last window's −sum, so the
 * accumulated sum equals [scalar]·G2.
 */
export function fixedBaseWindowPoint(
  w: number,
  k: number,
  numWindows: number,
): Point {
  const last = numWindows - 1;
  let scalar: bigint;
  if (w < last) {
    scalar = ((BigInt(k) + 2n) * H_BASE ** BigInt(w)) % FQ_MODULUS;
  } else {
    let sum = 0n;
    for (let j = 0; j < last; j++)
      sum = (sum + 2n ** (FBWS * BigInt(j) + 1n)) % FQ_MODULUS;
    scalar =
      (((BigInt(k) * H_BASE ** BigInt(w)) % FQ_MODULUS) - sum + FQ_MODULUS) %
      FQ_MODULUS;
  }
  return Pallas.scalarMul(scalar, G2_POINT);
}

/** Fixed-base mul accumulator: per-window added point + running accumulator. */
export function fixedBaseMul(windows: number[]): {
  points: Point[];
  accs: Point[];
  result: Point;
} {
  const n = windows.length;
  const points: Point[] = [];
  const accs: Point[] = [];
  let acc: Point = null;
  for (let w = 0; w < n; w++) {
    const p = fixedBaseWindowPoint(w, windows[w], n);
    points.push(p);
    acc = acc === null ? p : Pallas.add(acc, p);
    accs.push(acc);
  }
  return { points, accs, result: acc };
}

/**
 * Complete point addition witness (halo2_gadgets ecc/chip/add.rs) for P + Q = R,
 * with the inv0 helper cells the gate needs to select the case:
 *   α = inv0(x_q − x_p),  β = inv0(x_p),  γ = inv0(x_q),
 *   δ = inv0(y_q + y_p) when x_q = x_p else 0,
 *   λ = (y_q − y_p)·α          (distinct-x case),
 *   x_r = λ² − x_p − x_q,  y_r = λ(x_p − x_r) − y_p.
 */
export interface CompleteAdd {
  xr: bigint;
  yr: bigint;
  lambda: bigint;
  alpha: bigint;
  beta: bigint;
  gamma: bigint;
  delta: bigint;
}

const inv0 = (v: bigint): bigint => (v === 0n ? 0n : Fp.inv(v));

export function completeAdd(
  xp: bigint,
  yp: bigint,
  xq: bigint,
  yq: bigint,
): CompleteAdd {
  const alpha = inv0(Fp.sub(xq, xp));
  const beta = inv0(xp);
  const gamma = inv0(xq);
  const delta = xq === xp ? inv0(Fp.add(yq, yp)) : 0n;
  let lambda: bigint;
  if (xq !== xp) {
    lambda = Fp.mul(Fp.sub(yq, yp), alpha);
  } else {
    // Doubling: λ = 3·x_p² / (2·y_p).
    lambda = Fp.mul(Fp.mul(3n, Fp.square(xp)), inv0(Fp.add(yp, yp)));
  }
  const xr = Fp.sub(Fp.sub(Fp.square(lambda), xp), xq);
  const yr = Fp.sub(Fp.mul(lambda, Fp.sub(xp, xr)), yp);
  return { xr, yr, lambda, alpha, beta, gamma, delta };
}
