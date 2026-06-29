/**
 * Gadget B (history nullifier) — the tractable diff-accumulator witness (the
 * Poseidon commitment-hash chain is computed via the Poseidon module; the Pow5
 * in-circuit chip cells are a separate halo2_gadgets chip port).
 * For registration p_old = 0: diff[i] = (p_new[i])², diff_acc = running sum,
 * diff_inv = (final diff_acc)⁻¹ (non-zero proof).
 */
import { Fp } from '../field.js';

export const MAX_PASSWORD_LEN = 128;

export interface GadgetBDiffAcc {
  diff: bigint[];
  acc: bigint[];
  finalAcc: bigint;
  diffInv: bigint;
}

export function gadgetBDiffAcc(pNew: bigint[], pOld: bigint[], n = MAX_PASSWORD_LEN): GadgetBDiffAcc {
  const diff: bigint[] = [];
  const acc: bigint[] = [];
  let a = 0n;
  for (let i = 0; i < n; i++) {
    const pn = pNew[i] ?? 0n;
    const po = pOld[i] ?? 0n;
    const d = Fp.mul(Fp.sub(pn, po), Fp.sub(pn, po));
    a = Fp.add(a, d);
    diff.push(d);
    acc.push(a);
  }
  return { diff, acc, finalAcc: a, diffInv: a === 0n ? 0n : Fp.inv(a) };
}
