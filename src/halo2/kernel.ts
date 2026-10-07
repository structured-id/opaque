/**
 * The prover's parallel work, as operations of one lane: commitments
 * (MSMs over the SRS), inverse FFTs, the quotient of the coset classes the
 * lane holds, and the IPA's generator folding. A lane keeps the SRS and the
 * class evaluations of every loaded key, so a proof only ships its own
 * witness polynomials. Run in-thread by {@link LocalPool} or in a worker by
 * {@link serveKernel}.
 */
import { Vesta, type Point } from "../curve.js";
import { lagrangeToCoeff } from "../domain.js";
import type { Srs } from "./keygen.js";
import {
  butterflies,
  generators,
  groupFft,
  type ButterflyJob,
  type SrsWorkers,
} from "./srs.js";
import {
  CosetClass,
  classKey,
  quotientClass,
  type ClassKey,
  type KeyPolys,
  type ProofPolys,
  type QuotientChallenges,
  type QuotientShape,
} from "./quotient.js";

type Affine = NonNullable<Point>;

export type Basis = "g" | "lagrange";

/** A key as a lane needs it. */
export interface LaneKey {
  readonly shape: QuotientShape;
  readonly polys: KeyPolys;
}

export class Kernel {
  private srs: Srs | null = null;
  private readonly keys = new Map<
    string,
    { shape: QuotientShape; classes: ClassKey[] }
  >();

  init(srs: Srs): void {
    this.srs = srs;
  }

  private bases(basis: Basis): Affine[] {
    if (!this.srs) throw new Error("kernel used before init");
    return basis === "g" ? this.srs.g : this.srs.gLagrange;
  }

  /** Evaluate the key on the given classes and keep it under `id`. */
  loadKey(id: string, key: LaneKey, classes: number[]): void {
    const { k, extendedK } = key.shape;
    this.keys.set(id, {
      shape: key.shape,
      classes: classes.map((r) =>
        classKey(new CosetClass(r, k, extendedK), key.polys),
      ),
    });
  }

  hasKey(id: string): boolean {
    return this.keys.has(id);
  }

  /** Σ scalars[i]·basis[offset + i]. */
  msm(scalars: bigint[], basis: Basis, offset: number): Point {
    const b = this.bases(basis);
    return Vesta.msm(
      scalars,
      offset === 0 ? b : b.slice(offset, offset + scalars.length),
    );
  }

  /** Commit Lagrange values and return their coefficient form too. */
  advice(values: bigint[], k: number): { point: Point; poly: bigint[] } {
    return {
      point: this.msm(values, "lagrange", 0),
      poly: lagrangeToCoeff(values, k),
    };
  }

  quotient(
    id: string,
    polys: ProofPolys,
    ch: QuotientChallenges,
  ): { r: number; w: bigint[] }[] {
    const key = this.keys.get(id);
    if (!key) throw new Error(`key ${id} is not loaded`);
    return key.classes.map((ck) => ({
      r: ck.cls.r,
      w: quotientClass(key.shape, ck, polys, ch),
    }));
  }

  msmPoints(scalars: bigint[], points: Affine[]): Point {
    return Vesta.msm(scalars, points);
  }

  /** lo[i] + u·hi[i]. */
  fold(lo: Affine[], hi: Affine[], u: bigint): Point[] {
    return Vesta.addEach(lo, Vesta.mulEach(u, hi));
  }

  /** Commitment-key generators `start .. end` (needs no SRS). */
  generators(start: number, end: number): Affine[] {
    return generators(start, end - start);
  }

  /** A natural-order group DFT (needs no SRS). */
  groupFft(points: Point[], omega: bigint, k: number): Point[] {
    return groupFft(points, omega, k);
  }

  butterflies(job: ButterflyJob): [Point[], Point[]] {
    return butterflies(job.lo, job.hi, job.tw);
  }

  scale(points: Point[], s: bigint): Point[] {
    return Vesta.mulEach(s, points);
  }
}

/**
 * The operations a pool runs, lane-parallel where the work splits. The
 * commitment-key steps ({@link SrsWorkers}) need no `init`: they derive it.
 */
export interface ProverPool extends SrsWorkers {
  /** Parallel lanes (1 when everything runs in-thread). */
  readonly lanes: number;
  init(srs: Srs): Promise<void>;
  loadKey(id: string, key: LaneKey, classCount: number): Promise<void>;
  hasKey(id: string): boolean;
  /** One MSM per scalar vector over the basis (commitments without blinds). */
  msmMany(polys: bigint[][], basis: Basis): Promise<Point[]>;
  adviceMany(
    values: bigint[][],
    k: number,
  ): Promise<{ point: Point; poly: bigint[] }[]>;
  /** The interpolated quotient of every class, indexed by class. */
  quotient(
    id: string,
    polys: ProofPolys,
    ch: QuotientChallenges,
  ): Promise<bigint[][]>;
  msmPoints(scalars: bigint[], points: Affine[]): Promise<Point>;
  fold(lo: Affine[], hi: Affine[], u: bigint): Promise<Point[]>;
  close(): void;
}

/** Everything on the calling thread. */
export class LocalPool implements ProverPool {
  readonly lanes = 1;
  private readonly kernel = new Kernel();

  async init(srs: Srs): Promise<void> {
    this.kernel.init(srs);
  }

  async loadKey(id: string, key: LaneKey, classCount: number): Promise<void> {
    this.kernel.loadKey(
      id,
      key,
      Array.from({ length: classCount }, (_, r) => r),
    );
  }

  hasKey(id: string): boolean {
    return this.kernel.hasKey(id);
  }

  async msmMany(polys: bigint[][], basis: Basis): Promise<Point[]> {
    return polys.map((p) => this.kernel.msm(p, basis, 0));
  }

  async adviceMany(
    values: bigint[][],
    k: number,
  ): Promise<{ point: Point; poly: bigint[] }[]> {
    return values.map((v) => this.kernel.advice(v, k));
  }

  async quotient(
    id: string,
    polys: ProofPolys,
    ch: QuotientChallenges,
  ): Promise<bigint[][]> {
    const ws: bigint[][] = [];
    for (const { r, w } of this.kernel.quotient(id, polys, ch)) ws[r] = w;
    return ws;
  }

  async msmPoints(scalars: bigint[], points: Affine[]): Promise<Point> {
    return this.kernel.msmPoints(scalars, points);
  }

  async fold(lo: Affine[], hi: Affine[], u: bigint): Promise<Point[]> {
    return this.kernel.fold(lo, hi, u);
  }

  async generators(
    ranges: [number, number][],
    onDone?: () => void,
  ): Promise<Affine[][]> {
    return ranges.map(([s, e]) => {
      const pts = this.kernel.generators(s, e);
      onDone?.();
      return pts;
    });
  }

  async groupFfts(
    blocks: Point[][],
    omega: bigint,
    k: number,
  ): Promise<Point[][]> {
    return blocks.map((b) => this.kernel.groupFft(b, omega, k));
  }

  async butterflies(jobs: ButterflyJob[]): Promise<[Point[], Point[]][]> {
    return jobs.map((j) => this.kernel.butterflies(j));
  }

  async scale(chunks: Point[][], s: bigint): Promise<Point[][]> {
    return chunks.map((c) => this.kernel.scale(c, s));
  }

  close(): void {}
}
