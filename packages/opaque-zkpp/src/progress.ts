/**
 * ZKPP proof-progress model for a UI gauge. The halo2 IPA prover has well-defined
 * stages; weights are the measured time share at k=11 (advice MSMs ~36%, quotient
 * FFTs ~55%, rest small). A stage reports a sub-fraction [0,1]; the tracker maps it
 * to a monotonic overall [0,1] so the caller can drive a single gauge.
 */
export type ZkppStage =
  | 'witness'
  | 'commit-advice'
  | 'permutation'
  | 'lookups'
  | 'quotient'
  | 'evaluate'
  | 'multiopen'
  | 'ipa';

export interface ZkppProgress {
  /** Current stage. */
  stage: ZkppStage;
  /** Overall completion across all stages, 0..1 — drive the gauge with this. */
  fraction: number;
  /** Human-readable label for the current stage. */
  label: string;
}

const ORDER: ZkppStage[] = [
  'witness', 'commit-advice', 'permutation', 'lookups', 'quotient', 'evaluate', 'multiopen', 'ipa',
];

/** Time-share weights at k=11 (sum = 1.0), from the measured prover benchmark. */
const WEIGHTS: Record<ZkppStage, number> = {
  witness: 0.03,
  'commit-advice': 0.36,
  permutation: 0.01,
  lookups: 0.02,
  quotient: 0.55,
  evaluate: 0.01,
  multiopen: 0.01,
  ipa: 0.01,
};

const LABELS: Record<ZkppStage, string> = {
  witness: 'Building witness',
  'commit-advice': 'Committing columns',
  permutation: 'Permutation argument',
  lookups: 'Lookup arguments',
  quotient: 'Computing quotient',
  evaluate: 'Evaluating polynomials',
  multiopen: 'Opening commitments',
  ipa: 'Final proof',
};

export class ProgressTracker {
  private last = 0;
  constructor(private readonly cb?: (p: ZkppProgress) => void) {}

  /** Report progress within `stage`; `sub` ∈ [0,1]. Overall fraction is monotonic. */
  report(stage: ZkppStage, sub: number): void {
    if (!this.cb) return;
    const before = ORDER.slice(0, ORDER.indexOf(stage)).reduce((s, k) => s + WEIGHTS[k], 0);
    const clamped = sub < 0 ? 0 : sub > 1 ? 1 : sub;
    const overall = before + WEIGHTS[stage] * clamped;
    const fraction = overall < this.last ? this.last : overall; // never go backwards
    this.last = fraction;
    this.cb({ stage, fraction, label: LABELS[stage] });
  }

  /** Mark the whole proof complete (fraction = 1). */
  done(): void {
    this.last = 1;
    this.cb?.({ stage: 'ipa', fraction: 1, label: 'Done' });
  }
}
