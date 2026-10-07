/**
 * ZKPP proof-progress model for a UI gauge. The halo2 IPA prover runs its
 * stages in `create_proof` order; the weights are each stage's measured time
 * share at k=11 on the TypeScript prover (the quotient about half, the
 * permutation and the IPA a sixth each). A stage reports a sub-fraction
 * [0,1]; the tracker maps it to a monotonic overall [0,1] so the caller can
 * drive a single gauge.
 */
export type ZkppStage =
  | "witness"
  | "commit-advice"
  | "lookups"
  | "permutation"
  | "quotient"
  | "evaluate"
  | "multiopen"
  | "ipa";

export interface ZkppProgress {
  /** Current stage. */
  stage: ZkppStage;
  /** Overall completion across all stages, 0..1 — drive the gauge with this. */
  fraction: number;
  /** Completion of the current stage itself, 0..1 (for a {@link ProgressPlan}). */
  within: number;
  /** Human-readable label for the current stage. */
  label: string;
}

const ORDER: ZkppStage[] = [
  "witness",
  "commit-advice",
  "lookups",
  "permutation",
  "quotient",
  "evaluate",
  "multiopen",
  "ipa",
];

/** Time-share weights at k=11 (sum = 1.0), from bench/prove-profile.ts. */
const WEIGHTS: Record<ZkppStage, number> = {
  witness: 0.02,
  "commit-advice": 0.07,
  lookups: 0.03,
  permutation: 0.17,
  quotient: 0.52,
  evaluate: 0.01,
  multiopen: 0.02,
  ipa: 0.16,
};

/** The plan step a prover or key stage name belongs to. */
export function stepOf(name: string): ProgressStep {
  if (
    name === "download" ||
    name === "srs" ||
    name === "keygen" ||
    name === "load-key"
  )
    return name;
  return stageOf(name);
}

/** The progress stage a prover stage name belongs to. */
export function stageOf(name: string): ZkppStage {
  if (name.startsWith("quotient")) return "quotient";
  if (name === "load-key") return "witness";
  return (ORDER as string[]).includes(name) ? (name as ZkppStage) : "witness";
}

const LABELS: Record<ZkppStage, string> = {
  witness: "Building witness",
  "commit-advice": "Committing columns",
  permutation: "Permutation argument",
  lookups: "Lookup arguments",
  quotient: "Computing quotient",
  evaluate: "Evaluating polynomials",
  multiopen: "Opening commitments",
  ipa: "Final proof",
};

/** The steps of deriving a key: the commitment key, keygen, loading the lanes. */
export type PrepareStep = "srs" | "keygen" | "load-key";

/**
 * A step of a plan: fetching a large artifact (the native kernel's module),
 * deriving the key, or a stage of the proof.
 */
export type ProgressStep = "download" | PrepareStep | ZkppStage;

export const PREPARE_STEPS: PrepareStep[] = ["srs", "keygen", "load-key"];
export const PROVE_STEPS: ZkppStage[] = [...ORDER];

/**
 * Step times (ms) a plan starts from before it has measured anything: the
 * TypeScript client on a mid-range phone, the proof split by the profiled
 * stage shares, and a 1.7 MB module over a slow mobile link (about 1 Mbit/s).
 * A plan replaces them with what it measures on the device.
 */
export const DEFAULT_STEP_MS: Record<ProgressStep, number> = {
  download: 14000,
  srs: 4400,
  keygen: 4400,
  "load-key": 1000,
  witness: 60,
  "commit-advice": 220,
  lookups: 100,
  permutation: 540,
  quotient: 1660,
  evaluate: 30,
  multiopen: 60,
  ipa: 510,
};

export interface PlanSegment {
  step: ProgressStep;
  /** Where the segment starts and how wide it is, as shares of the bar. */
  start: number;
  width: number;
}

export interface ProgressPlanOptions {
  /** Expected step times (ms); missing steps take {@link DEFAULT_STEP_MS}. */
  estimates?: Partial<Record<ProgressStep, number>>;
  /** Smallest share of the bar a step gets, so short steps stay visible. */
  minShare?: number;
  /** Weight of the newest measurement in the moving average. */
  alpha?: number;
  /** Clock, ms (tests pass their own). */
  now?: () => number;
}

/**
 * One bar over several steps (a key derivation and a proof, say). Each step
 * gets a width in proportion to its expected time, an exponential moving
 * average of what it took before on this device, with a floor so no step
 * vanishes. Inside a step the bar follows the step's own reports and, between
 * them, the elapsed time against the expected one, stopping short of the
 * step's end until the step reports done. It never moves backwards.
 */
export class ProgressPlan {
  readonly segments: PlanSegment[];
  private readonly estimates: Record<ProgressStep, number>;
  private readonly alpha: number;
  private readonly now: () => number;
  private current = -1;
  private stepStart = 0;
  private reported = 0;
  private last = 0;
  private readonly measured: Partial<Record<ProgressStep, number>> = {};

  constructor(steps: ProgressStep[], opts: ProgressPlanOptions = {}) {
    if (steps.length === 0) throw new Error("a progress plan needs steps");
    this.estimates = { ...DEFAULT_STEP_MS, ...opts.estimates };
    this.alpha = opts.alpha ?? 0.3;
    this.now = opts.now ?? (() => performance.now());
    const minShare = Math.min(opts.minShare ?? 0.02, 1 / steps.length);
    const total = steps.reduce((s, k) => s + this.estimates[k], 0);
    // Shares in proportion to time, then the floor taken from the larger ones.
    const raw = steps.map((k) => this.estimates[k] / total);
    const short = raw.filter((r) => r < minShare);
    const spare = 1 - short.length * minShare;
    const longTotal = raw
      .filter((r) => r >= minShare)
      .reduce((s, r) => s + r, 0);
    let start = 0;
    this.segments = steps.map((step, i) => {
      const width = raw[i] < minShare ? minShare : (raw[i] / longTotal) * spare;
      const seg = { step, start, width };
      start += width;
      return seg;
    });
  }

  /** `step` has reached `fraction` of its own work. */
  report(step: ProgressStep, fraction: number): void {
    const i = this.segments.findIndex((s) => s.step === step);
    if (i < 0) return;
    const t = this.now();
    if (i > this.current) {
      // Every step between the old and the new one is over; time the old.
      if (this.current >= 0) this.measure(this.current, t);
      this.current = i;
      this.stepStart = t;
      this.reported = 0;
    }
    if (i === this.current)
      this.reported = Math.max(
        this.reported,
        Math.min(1, Math.max(0, fraction)),
      );
  }

  private measure(i: number, t: number): void {
    const step = this.segments[i].step;
    this.measured[step] = t - this.stepStart;
  }

  /** The bar's position now, 0..1. */
  fraction(): number {
    if (this.current < 0) return this.last;
    const seg = this.segments[this.current];
    const expected = this.estimates[seg.step];
    const byTime = Math.min(0.95, (this.now() - this.stepStart) / expected);
    const within = Math.max(this.reported, byTime);
    this.last = Math.max(this.last, seg.start + seg.width * within);
    return this.last;
  }

  /** The step the bar is in, if any. */
  step(): ProgressStep | null {
    return this.current < 0 ? null : this.segments[this.current].step;
  }

  /**
   * Close the plan: time the last step and return the estimates moved
   * toward what was measured, for the next plan on this device.
   */
  finish(): Record<ProgressStep, number> {
    if (this.current >= 0) this.measure(this.current, this.now());
    this.last = 1;
    const next = { ...this.estimates };
    for (const [step, ms] of Object.entries(this.measured) as [
      ProgressStep,
      number,
    ][])
      next[step] = next[step] * (1 - this.alpha) + ms * this.alpha;
    return next;
  }
}

export class ProgressTracker {
  private last = 0;
  constructor(private readonly cb?: (p: ZkppProgress) => void) {}

  /** Report progress within `stage`; `sub` ∈ [0,1]. Overall fraction is monotonic. */
  report(stage: ZkppStage, sub: number): void {
    if (!this.cb) return;
    const before = ORDER.slice(0, ORDER.indexOf(stage)).reduce(
      (s, k) => s + WEIGHTS[k],
      0,
    );
    const clamped = sub < 0 ? 0 : sub > 1 ? 1 : sub;
    const overall = before + WEIGHTS[stage] * clamped;
    const fraction = overall < this.last ? this.last : overall; // never go backwards
    this.last = fraction;
    this.cb({ stage, fraction, within: clamped, label: LABELS[stage] });
  }

  /** Mark the whole proof complete (fraction = 1). */
  done(): void {
    this.last = 1;
    this.cb?.({ stage: "ipa", fraction: 1, within: 1, label: "Done" });
  }
}
