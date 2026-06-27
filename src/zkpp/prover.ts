/**
 * Pure-TS halo2 IPA prover (port of halo2 create_proof, over Vesta). Built and
 * verified step-by-step against a deterministic Rust reference proof (toy circuit,
 * counter RNG). This module accumulates the create_proof pipeline:
 *   advice commit → theta → lookups → beta/gamma → permutation → y → vanishing →
 *   x → evaluations → multiopen → IPA opening.
 */
import { Fp } from './field.js';
import { Vesta, type Point } from './curve.js';

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
