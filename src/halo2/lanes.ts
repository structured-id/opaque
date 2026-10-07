/**
 * A {@link ProverPool} over worker lanes. Each lane runs a {@link Kernel}
 * behind a message port; the pool hands whole columns to whichever lane is
 * free, splits a lone MSM or folding across all lanes and sums the parts,
 * and gives each lane the coset classes r ≡ lane (mod lanes). Values cross
 * by structured clone (bigints included), so any worker implementation with
 * `postMessage` and `onmessage` serves: a Web Worker in the browser,
 * `worker_threads` in Node.
 */
import { Vesta, type Point } from "../curve.js";
import type { Srs } from "./keygen.js";
import { Kernel, type Basis, type LaneKey, type ProverPool } from "./kernel.js";
import type { ProofPolys, QuotientChallenges } from "./quotient.js";
import type { ButterflyJob } from "./srs.js";

type Affine = NonNullable<Point>;

/** The side of a worker the pool talks to. */
export interface LaneWorker {
  postMessage(message: unknown): void;
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror?: ((event: unknown) => void) | null;
  terminate(): void;
}

/** The side of a worker the kernel listens on. */
export interface LaneEndpoint {
  postMessage(message: unknown): void;
  onmessage: ((event: { data: unknown }) => void) | null;
}

type Op =
  | "init"
  | "loadKey"
  | "msm"
  | "advice"
  | "quotient"
  | "msmPoints"
  | "fold"
  | "generators"
  | "groupFft"
  | "butterflies"
  | "scale";

interface Request {
  id: number;
  op: Op;
  args: unknown[];
}

type Reply =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: string };

/** Answer pool requests on `endpoint` with a fresh kernel. */
export function serveKernel(endpoint: LaneEndpoint): void {
  const kernel = new Kernel();
  const ops: Record<Op, (...args: never[]) => unknown> = {
    init: (srs: Srs) => kernel.init(srs),
    loadKey: (id: string, key: LaneKey, classes: number[]) =>
      kernel.loadKey(id, key, classes),
    msm: (s: bigint[], b: Basis, off: number) => kernel.msm(s, b, off),
    advice: (v: bigint[], k: number) => kernel.advice(v, k),
    quotient: (id: string, p: ProofPolys, ch: QuotientChallenges) =>
      kernel.quotient(id, p, ch),
    msmPoints: (s: bigint[], p: Affine[]) => kernel.msmPoints(s, p),
    fold: (lo: Affine[], hi: Affine[], u: bigint) => kernel.fold(lo, hi, u),
    generators: (s: number, e: number) => kernel.generators(s, e),
    groupFft: (p: Point[], omega: bigint, k: number) =>
      kernel.groupFft(p, omega, k),
    butterflies: (job: ButterflyJob) => kernel.butterflies(job),
    scale: (p: Point[], s: bigint) => kernel.scale(p, s),
  };
  endpoint.onmessage = (event) => {
    const { id, op, args } = event.data as Request;
    let reply: Reply;
    try {
      reply = {
        id,
        ok: true,
        result: (ops[op] as (...a: unknown[]) => unknown)(...args),
      };
    } catch (err) {
      reply = {
        id,
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
    endpoint.postMessage(reply);
  };
}

/**
 * How many lanes may compute at once. A background tab gets a small CPU
 * budget for the whole page, so running every lane there only makes them
 * contend; the pool then lets fewer run, each keeping the work it holds.
 */
class Limiter {
  private running = 0;
  private readonly waiting: (() => void)[] = [];

  constructor(private limit: number) {}

  set(limit: number): void {
    this.limit = limit;
    this.pump();
  }

  acquire(): Promise<void> {
    return new Promise((resolve) => {
      this.waiting.push(resolve);
      this.pump();
    });
  }

  release(): void {
    this.running--;
    this.pump();
  }

  private pump(): void {
    while (this.running < this.limit && this.waiting.length > 0) {
      this.running++;
      (this.waiting.shift() as () => void)();
    }
  }
}

class Lane {
  private next = 1;
  private readonly pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >();
  /** Why the lane stopped; every call fails with it from then on. */
  private stopped: Error | undefined;

  constructor(
    readonly worker: LaneWorker,
    private readonly limiter: Limiter,
  ) {
    worker.onmessage = (event) => {
      const reply = event.data as Reply;
      const p = this.pending.get(reply.id);
      if (!p) return;
      this.pending.delete(reply.id);
      if (reply.ok) p.resolve(reply.result);
      else p.reject(new Error(reply.error));
    };
    // A lane that reported an error answers nothing again.
    worker.onerror = (event) => {
      this.stopped ??= new Error(`prover lane failed: ${String(event)}`);
      for (const p of this.pending.values()) p.reject(this.stopped);
      this.pending.clear();
    };
  }

  async call<T>(op: Op, ...args: unknown[]): Promise<T> {
    if (this.stopped) throw this.stopped;
    await this.limiter.acquire();
    try {
      // The lane may have stopped while this call waited for a slot.
      if (this.stopped) throw this.stopped;
      const id = this.next++;
      return await new Promise<T>((resolve, reject) => {
        this.pending.set(id, {
          resolve: resolve as (v: unknown) => void,
          reject,
        });
        this.worker.postMessage({ id, op, args } satisfies Request);
      });
    } finally {
      this.limiter.release();
    }
  }
}

/** Contiguous [start, end) ranges splitting `len` items over `parts`. */
function ranges(len: number, parts: number): [number, number][] {
  const out: [number, number][] = [];
  const size = Math.ceil(len / parts);
  for (let s = 0; s < len; s += size) out.push([s, Math.min(len, s + size)]);
  return out;
}

const sum = (ps: Point[]): Point =>
  ps.reduce<Point>((acc, p) => Vesta.add(acc, p), null);

export class WorkerPool implements ProverPool {
  readonly lanes: number;
  private readonly workers: Lane[];
  private readonly keys = new Set<string>();
  private readonly limiter: Limiter;

  constructor(spawn: () => LaneWorker, lanes: number) {
    if (lanes < 1) throw new Error("a pool needs at least one lane");
    this.lanes = lanes;
    this.limiter = new Limiter(lanes);
    this.workers = Array.from(
      { length: lanes },
      () => new Lane(spawn(), this.limiter),
    );
  }

  /**
   * Let at most `n` lanes compute at once (all of them by default). Work
   * stays on the lane that holds it, so changing this moves nothing.
   */
  setActive(n: number): void {
    this.limiter.set(Math.max(1, Math.min(this.lanes, Math.floor(n))));
  }

  /** Run tasks on whichever lane is free next; results in task order. */
  private async queue<R>(
    count: number,
    task: (lane: Lane, i: number) => Promise<R>,
  ): Promise<R[]> {
    const out = new Array<R>(count);
    let next = 0;
    await Promise.all(
      this.workers.map(async (lane) => {
        while (next < count) {
          const i = next++;
          out[i] = await task(lane, i);
        }
      }),
    );
    return out;
  }

  async init(srs: Srs): Promise<void> {
    await Promise.all(this.workers.map((w) => w.call("init", srs)));
  }

  async loadKey(id: string, key: LaneKey, classCount: number): Promise<void> {
    await Promise.all(
      this.workers.map((w, lane) => {
        const classes: number[] = [];
        for (let r = lane; r < classCount; r += this.lanes) classes.push(r);
        return w.call("loadKey", id, key, classes);
      }),
    );
    this.keys.add(id);
  }

  hasKey(id: string): boolean {
    return this.keys.has(id);
  }

  async msmMany(polys: bigint[][], basis: Basis): Promise<Point[]> {
    if (polys.length >= this.lanes)
      return this.queue(polys.length, (lane, i) =>
        lane.call<Point>("msm", polys[i], basis, 0),
      );
    return Promise.all(
      polys.map(async (p) => {
        const parts = ranges(p.length, this.lanes);
        return sum(
          await Promise.all(
            parts.map(([s, e], lane) =>
              this.workers[lane].call<Point>("msm", p.slice(s, e), basis, s),
            ),
          ),
        );
      }),
    );
  }

  adviceMany(
    values: bigint[][],
    k: number,
  ): Promise<{ point: Point; poly: bigint[] }[]> {
    return this.queue(values.length, (lane, i) =>
      lane.call("advice", values[i], k),
    );
  }

  async quotient(
    id: string,
    polys: ProofPolys,
    ch: QuotientChallenges,
  ): Promise<bigint[][]> {
    const parts = await Promise.all(
      this.workers.map((w) =>
        w.call<{ r: number; w: bigint[] }[]>("quotient", id, polys, ch),
      ),
    );
    const ws: bigint[][] = [];
    for (const part of parts) for (const { r, w } of part) ws[r] = w;
    return ws;
  }

  async msmPoints(scalars: bigint[], points: Affine[]): Promise<Point> {
    const parts = ranges(scalars.length, this.lanes);
    return sum(
      await Promise.all(
        parts.map(([s, e], lane) =>
          this.workers[lane].call<Point>(
            "msmPoints",
            scalars.slice(s, e),
            points.slice(s, e),
          ),
        ),
      ),
    );
  }

  async fold(lo: Affine[], hi: Affine[], u: bigint): Promise<Point[]> {
    const parts = ranges(lo.length, this.lanes);
    const folded = await Promise.all(
      parts.map(([s, e], lane) =>
        this.workers[lane].call<Point[]>(
          "fold",
          lo.slice(s, e),
          hi.slice(s, e),
          u,
        ),
      ),
    );
    return folded.flat();
  }

  generators(
    ranges: [number, number][],
    onDone?: () => void,
  ): Promise<Affine[][]> {
    return this.queue(ranges.length, async (lane, i) => {
      const pts = await lane.call<Affine[]>("generators", ...ranges[i]);
      onDone?.();
      return pts;
    });
  }

  groupFfts(blocks: Point[][], omega: bigint, k: number): Promise<Point[][]> {
    return this.queue(blocks.length, (lane, i) =>
      lane.call<Point[]>("groupFft", blocks[i], omega, k),
    );
  }

  butterflies(jobs: ButterflyJob[]): Promise<[Point[], Point[]][]> {
    return this.queue(jobs.length, (lane, i) =>
      lane.call<[Point[], Point[]]>("butterflies", jobs[i]),
    );
  }

  scale(chunks: Point[][], s: bigint): Promise<Point[][]> {
    return this.queue(chunks.length, (lane, i) =>
      lane.call<Point[]>("scale", chunks[i], s),
    );
  }

  close(): void {
    for (const w of this.workers) w.worker.terminate();
  }
}
