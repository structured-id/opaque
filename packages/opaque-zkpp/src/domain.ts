/**
 * Evaluation domain helpers — byte-identical to halo2 `EvaluationDomain`.
 *   coeff_to_extended: shift coefficients into the ζ-coset (a[i] *= ζ^(i mod 3),
 *   ζ a cube root of unity in Fp), zero-pad to the extended domain 2^extended_k,
 *   then NTT with the extended root of unity. Used to evaluate the quotient.
 */
import { Fp } from './field.js';
import { bestFft, omegaForSize } from './fft.js';

const leHex = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};

/** Fp::ZETA — a primitive cube root of unity (the coset shift base). ζ³ = 1. */
export const ZETA = leHex('b94afefdbd5ead1d4931ad37d28b1f1db0b1aa57dcd5aa2c71bacd4a83cacc12');
const ZETA2 = Fp.square(ZETA);

/** Multiply a[i] by ζ^(i mod 3) in place (move into the coset). */
function distributePowersZeta(a: bigint[]): void {
  for (let i = 0; i < a.length; i++) {
    const m = i % 3;
    if (m === 1) a[i] = Fp.mul(a[i], ZETA);
    else if (m === 2) a[i] = Fp.mul(a[i], ZETA2);
  }
}

/** Coefficient polynomial → extended Lagrange (coset) evaluations over 2^extendedK. */
export function coeffToExtended(coeffs: bigint[], extendedK: number): bigint[] {
  const a = coeffs.map((c) => Fp.mod(c));
  distributePowersZeta(a);
  const extLen = 1 << extendedK;
  while (a.length < extLen) a.push(0n);
  bestFft(a, omegaForSize(extendedK), extendedK);
  return a;
}

/** Inverse NTT in place: bestFft with ω⁻¹ then scale by `divisor` (= sizeⁿ⁻¹). */
function ifft(a: bigint[], omegaInv: bigint, logN: number, divisor: bigint): void {
  bestFft(a, omegaInv, logN);
  for (let i = 0; i < a.length; i++) a[i] = Fp.mul(a[i], divisor);
}

/** Lagrange evaluations (size 2^k) → coefficient polynomial (halo2 lagrange_to_coeff). */
export function lagrangeToCoeff(a: bigint[], k: number): bigint[] {
  const n = 1 << k;
  const out = a.map((v) => Fp.mod(v));
  ifft(out, Fp.inv(omegaForSize(k)), k, Fp.inv(BigInt(n)));
  return out;
}

/** Undo the ζ-coset shift: a[i] *= ζ^(-(i mod 3)) (coset_powers reversed). */
function distributePowersZetaInverse(a: bigint[]): void {
  for (let i = 0; i < a.length; i++) {
    const m = i % 3;
    if (m === 1) a[i] = Fp.mul(a[i], ZETA2);
    else if (m === 2) a[i] = Fp.mul(a[i], ZETA);
  }
}

/**
 * Extended coset evaluations → coefficient polynomial (halo2 extended_to_coeff):
 * inverse extended NTT, undo the ζ-coset shift, truncate to n·quotientPolyDegree.
 */
export function extendedToCoeff(
  a: bigint[],
  k: number,
  extendedK: number,
  quotientPolyDegree: number,
): bigint[] {
  const out = a.map((v) => Fp.mod(v));
  ifft(out, Fp.inv(omegaForSize(extendedK)), extendedK, Fp.inv(BigInt(1 << extendedK)));
  distributePowersZetaInverse(out);
  return out.slice(0, (1 << k) * quotientPolyDegree);
}

/** 1/t(X) evaluations on the ζ-coset, period 2^(extendedK-k) (halo2 t_evaluations). */
export function vanishingTInv(k: number, extendedK: number): bigint[] {
  const period = 1 << (extendedK - k);
  const n = BigInt(1 << k);
  const extOmegaN = Fp.pow(omegaForSize(extendedK), n);
  let cur = Fp.pow(ZETA, n); // ζⁿ
  const t: bigint[] = [];
  for (let i = 0; i < period; i++) {
    t.push(Fp.inv(Fp.sub(cur, 1n)));
    cur = Fp.mul(cur, extOmegaN);
  }
  return t;
}

/** Divide an extended-coset polynomial by t(X)=Xⁿ-1: a[i] *= tInv[i mod period]. */
export function divideByVanishing(a: bigint[], tInv: bigint[]): bigint[] {
  return a.map((v, i) => Fp.mul(v, tInv[i % tInv.length]));
}
