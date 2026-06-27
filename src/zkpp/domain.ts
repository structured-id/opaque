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
