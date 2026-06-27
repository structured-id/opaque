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
