/**
 * Pure-TS halo2 IPA prover (port of halo2 create_proof, over Vesta). Built and
 * verified step-by-step against a deterministic Rust reference proof (toy circuit,
 * counter RNG). This module accumulates the create_proof pipeline:
 *   advice commit → theta → lookups → beta/gamma → permutation → y → vanishing →
 *   x → evaluations → multiopen → IPA opening.
 */
import { Fp } from './field.js';
import { Vesta, type Point } from './curve.js';
import { omegaForSize } from './fft.js';
import { ZETA } from './domain.js';

/** Fp::DELTA — the permutation argument's coset separator (column j uses δ^j). */
export const DELTA = (() => {
  const h = 'a29b7bdd20cd6c6a3656ee3ef1f3e4f59d04a512715b45bd6cab06000f7d750a';
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
})();

/** Deterministic RNG matching the Rust CounterRng: byte stream 0,1,2,…,255,0,… */
export class CounterRng {
  private ctr = 0;
  /** Next field scalar = Fp.from_uniform_bytes(next 64 counter bytes). */
  nextScalar(): bigint {
    const b = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      b[i] = this.ctr & 0xff;
      this.ctr = (this.ctr + 1) & 0xff;
    }
    return Fp.fromUniformBytes(b);
  }
}

export interface ProvingParams {
  /** Lagrange-basis IPA generators g_lagrange[0..n). */
  gLagrange: { x: bigint; y: bigint }[];
  /** Blinding generator w. */
  w: { x: bigint; y: bigint };
  /** Domain size n = 2^k. */
  n: number;
  /** Number of blinding-factor rows. */
  blindingFactors: number;
}

export interface AdviceCommitResult {
  commitments: Point[];
  blinds: bigint[];
  advice: bigint[][];
}

/**
 * First create_proof step: randomize the blinding rows of each advice column
 * (rows [n-(bf+1), n)), draw a per-column commitment blind, and commit each column
 * in Lagrange basis (Σ aᵢ·g_lagrangeᵢ + blind·w). RNG order matches halo2: all
 * blinding rows first (column-major), then the blinds.
 */
export function commitAdvice(
  params: ProvingParams,
  adviceCols: bigint[][],
  rng: CounterRng,
): AdviceCommitResult {
  const { n, blindingFactors, gLagrange, w } = params;
  const unusableStart = n - (blindingFactors + 1);

  const advice = adviceCols.map((c) => {
    const col = c.map((v) => Fp.mod(v));
    while (col.length < n) col.push(0n);
    return col;
  });
  for (const col of advice) {
    for (let r = unusableStart; r < n; r++) col[r] = rng.nextScalar();
  }
  const blinds = advice.map(() => rng.nextScalar());
  const commitments = advice.map((col, i) =>
    Vesta.add(Vesta.msm(col, gLagrange), Vesta.scalarMul(blinds[i], w)),
  );
  return { commitments, blinds, advice };
}

/**
 * Permutation grand-product polynomial Z for one column chunk (chunk_len=1 here),
 * byte-identical to halo2 permutation::prover. For column j with values `col`,
 * permuted (σ) values `sigma`, and delta power δ^j:
 *   modified[i] = (col[i] + δ^j·ωⁱ·β + γ) / (col[i] + β·σ[i] + γ)
 *   Z[0] = lastZ;  Z[i] = Z[i-1]·modified[i-1]
 * Returns Z (length n); the carry-over lastZ for the next chunk is Z[n-(bf+1)].
 */
export function permutationZ(
  col: bigint[],
  sigma: bigint[],
  beta: bigint,
  gamma: bigint,
  deltaPow: bigint,
  k: number,
  lastZ: bigint,
): bigint[] {
  const n = 1 << k;
  const omega = omegaForSize(k);
  // Denominator col[i] + β·σ[i] + γ, then invert.
  const modified = col.map((v, i) => Fp.add(Fp.add(v, Fp.mul(beta, sigma[i])), gamma));
  for (let i = 0; i < n; i++) modified[i] = Fp.inv(modified[i]);
  // Multiply by numerator col[i] + δ^j·ωⁱ·β + γ.
  let dw = deltaPow;
  for (let i = 0; i < n; i++) {
    modified[i] = Fp.mul(modified[i], Fp.add(Fp.add(Fp.mul(dw, beta), gamma), col[i]));
    dw = Fp.mul(dw, omega);
  }
  // Grand product.
  const z = [lastZ];
  for (let i = 1; i < n; i++) z.push(Fp.mul(z[i - 1], modified[i - 1]));
  return z;
}

/**
 * Commit each permutation grand-product polynomial: overwrite the last
 * `blindingFactors` rows (z[n-bf, n)) with RNG randomness, draw a commitment
 * blind, and commit in Lagrange basis. RNG order (per chunk): bf blinding rows
 * then the blind — matching halo2 permutation::prover. Must continue the same
 * CounterRng used for commitAdvice.
 */
export function commitPermutationZ(
  params: ProvingParams,
  zPolys: bigint[][],
  rng: CounterRng,
): { commitments: Point[]; blindedZ: bigint[][] } {
  const { n, blindingFactors, gLagrange, w } = params;
  const commitments: Point[] = [];
  const blindedZ: bigint[][] = [];
  for (const z of zPolys) {
    const zc = z.slice();
    for (let r = n - blindingFactors; r < n; r++) zc[r] = rng.nextScalar();
    const blind = rng.nextScalar();
    commitments.push(Vesta.add(Vesta.msm(zc, gLagrange), Vesta.scalarMul(blind, w)));
    blindedZ.push(zc);
  }
  return { commitments, blindedZ };
}

/**
 * Vanishing argument's random blinding commitment: a degree n-1 polynomial of RNG
 * coefficients committed in the COEFFICIENT basis (params.commit, gCoeff) plus a
 * random blind. Absorbed before the y challenge. RNG: n coeffs then the blind.
 */
export function commitVanishingRandom(
  gCoeff: { x: bigint; y: bigint }[],
  w: { x: bigint; y: bigint },
  n: number,
  rng: CounterRng,
): Point {
  const coeffs = Array.from({ length: n }, () => rng.nextScalar());
  const blind = rng.nextScalar();
  return Vesta.add(Vesta.msm(coeffs, gCoeff), Vesta.scalarMul(blind, w));
}

/**
 * Commit the quotient h(X) split into n-sized pieces (coefficient basis), each
 * with an RNG blind. RNG: one blind per piece, continuing the same CounterRng.
 */
export function commitHPieces(
  gCoeff: { x: bigint; y: bigint }[],
  w: { x: bigint; y: bigint },
  hPoly: bigint[],
  n: number,
  rng: CounterRng,
): Point[] {
  const out: Point[] = [];
  for (let off = 0; off < hPoly.length; off += n) {
    const piece = hPoly.slice(off, off + n);
    const blind = rng.nextScalar();
    out.push(Vesta.add(Vesta.msm(piece, gCoeff), Vesta.scalarMul(blind, w)));
  }
  return out;
}

/**
 * Vanishing-argument folded constraint polynomial H on the extended coset
 * (halo2 distribute_powers(expressions, y) then evaluate), for the toy circuit
 * a·b=c with a 3-set permutation. Expression order matches halo2:
 *   gate, perm-first-set, perm-last-set, perm-inter-sets, perm-main-per-set.
 * Folded by Horner with y (first expression gets the highest power).
 */
export interface FoldedHCosets {
  adv0: bigint[];
  adv1: bigint[];
  inst: bigint[];
  sel: bigint[];
  z: bigint[][];
  sigma: bigint[][];
  l0: bigint[];
  lLast: bigint[];
  lBlind: bigint[];
}

export function buildFoldedH(
  c: FoldedHCosets,
  beta: bigint,
  gamma: bigint,
  y: bigint,
  k: number,
  extendedK: number,
  blindingFactors: number,
): bigint[] {
  const extN = 1 << extendedK;
  const omegaExt = omegaForSize(extendedK);
  const rotMul = 1 << (extendedK - k);
  const rotNext = rotMul; // Rotation::next() = +1 row
  const rotLast = -(blindingFactors + 1) * rotMul; // Rotation(-(bf+1))
  const at = (a: bigint[], i: number, shift: number) => a[(((i + shift) % extN) + extN) % extN];
  // X polynomial on the ζ-coset: X[i] = ζ·ω_extⁱ.
  const X: bigint[] = [];
  let wv = ZETA;
  for (let i = 0; i < extN; i++) {
    X.push(wv);
    wv = Fp.mul(wv, omegaExt);
  }
  const cols = [c.adv0, c.adv1, c.inst];
  const exprs: bigint[][] = [];
  const mk = (f: (i: number) => bigint) => Array.from({ length: extN }, (_, i) => f(i));

  // Gate: selector·(adv0·adv1 - adv0@next).
  exprs.push(mk((i) => Fp.mul(c.sel[i], Fp.sub(Fp.mul(c.adv0[i], c.adv1[i]), at(c.adv0, i, rotNext)))));
  // Permutation, first set: (1 - Z_0)·l0.
  exprs.push(mk((i) => Fp.mul(Fp.sub(1n, c.z[0][i]), c.l0[i])));
  // Permutation, last set: (Z_last² - Z_last)·l_last.
  exprs.push(mk((i) => Fp.mul(Fp.sub(Fp.square(c.z[2][i]), c.z[2][i]), c.lLast[i])));
  // Permutation, inter-set: (Z_i - Z_{i-1}@last_rotation)·l0.
  for (let s = 1; s < 3; s++) {
    exprs.push(mk((i) => Fp.mul(Fp.sub(c.z[s][i], at(c.z[s - 1], i, rotLast)), c.l0[i])));
  }
  // Permutation, main identity per set: (left - right)·(1 - (l_last + l_blind)).
  for (let s = 0; s < 3; s++) {
    const col = cols[s];
    const sig = c.sigma[s];
    const cd0 = Fp.mul(beta, Fp.pow(DELTA, BigInt(s)));
    exprs.push(
      mk((i) => {
        const left = Fp.mul(at(c.z[s], i, rotNext), Fp.add(Fp.add(col[i], Fp.mul(beta, sig[i])), gamma));
        const right = Fp.mul(c.z[s][i], Fp.add(Fp.add(col[i], Fp.mul(cd0, X[i])), gamma));
        return Fp.mul(Fp.sub(left, right), Fp.sub(1n, Fp.add(c.lLast[i], c.lBlind[i])));
      }),
    );
  }
  // Fold by Horner: acc = acc·y + e (first expression highest power).
  const H = new Array<bigint>(extN).fill(0n);
  for (const e of exprs) for (let i = 0; i < extN; i++) H[i] = Fp.add(Fp.mul(H[i], y), e[i]);
  return H;
}
