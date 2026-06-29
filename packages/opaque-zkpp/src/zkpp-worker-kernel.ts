/**
 * Per-column proving kernel: commits one advice column (MSM) and computes its
 * extended-domain FFT. This SAME function is the Web Worker payload AND the
 * single-thread fallback in worker-pool.ts, so both paths are byte-identical.
 *
 * NOTE: SRS here is a deterministic incremental basis (placeholder for the real
 * k=11 Params generators); swap for the real SRS when params are ported.
 */
import { Vesta } from './curve.js';
import { coeffToExtended } from './domain.js';

let srsCache: { x: bigint; y: bigint }[] | null = null;
function srs(n: number): { x: bigint; y: bigint }[] {
  if (srsCache && srsCache.length >= n) return srsCache;
  const G = Vesta.GENERATOR;
  const pts: { x: bigint; y: bigint }[] = [G];
  let p: { x: bigint; y: bigint } | null = G;
  for (let i = 1; i < n; i++) { p = Vesta.add(p, G) as { x: bigint; y: bigint }; pts.push(p); }
  srsCache = pts;
  return pts;
}

export interface ColumnTask {
  scalars: bigint[];
  extendedK: number;
}
export interface ColumnResult {
  commitment: { x: bigint; y: bigint } | null;
  ext: bigint[];
}

/** Commit (MSM, skipping zero scalars) + extended FFT for one advice column. */
export function processColumn(t: ColumnTask): ColumnResult {
  const S = srs(t.scalars.length);
  const pts: { x: bigint; y: bigint }[] = [];
  const scs: bigint[] = [];
  for (let i = 0; i < t.scalars.length; i++) {
    if (t.scalars[i] !== 0n) { pts.push(S[i]); scs.push(t.scalars[i]); }
  }
  const commitment = scs.length ? (Vesta.msm(scs, pts) as { x: bigint; y: bigint } | null) : null;
  const ext = coeffToExtended(t.scalars, t.extendedK);
  return { commitment, ext };
}
