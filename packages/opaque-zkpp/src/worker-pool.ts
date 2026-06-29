/**
 * CPU-bound parallel map with a mandatory single-thread fallback. The pure-TS ZKPP
 * prover's heavy work (independent per-column MSMs and FFTs) is embarrassingly
 * parallel; running it across a Web Worker pool gives ~Ncores× (measured 3.7× on a
 * 4-core laptop). When Web Workers are unavailable (no `Worker`, CSP, or worker
 * construction throws), or only one core is usable, it runs INLINE on the caller's
 * thread so proving always works — just slower.
 */

/** True only if the runtime exposes the Web Worker constructor. */
export function workersAvailable(): boolean {
  return typeof Worker !== 'undefined';
}

/** Usable hardware concurrency (defaults to 1 when unknown → forces fallback). */
export function hwConcurrency(): number {
  const n = typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : undefined;
  return typeof n === 'number' && n > 0 ? n : 1;
}

export interface WorkerSpec<T, R> {
  /** URL of the worker module (must postMessage the result of one item). */
  url: URL;
  /** Serialise an item into a structured-cloneable worker message. */
  toMessage: (item: T, index: number) => unknown;
  /** Parse a worker reply back into a result. */
  fromMessage: (msg: unknown) => R;
  /**
   * Optional one-time payload posted to each worker before any task (e.g. the SRS
   * for MSM). The worker must treat its first message as this init and reply once
   * (any value) to signal ready; subsequent messages are tasks.
   */
  initMessage?: unknown;
}

export interface ParallelOptions {
  maxWorkers?: number;
  /** Called after each item completes (any path) — drive a progress gauge. */
  onTick?: (done: number, total: number) => void;
}

/**
 * Map `items` through CPU-bound work. Uses a Web Worker pool when `spec` is given
 * and workers are usable; otherwise runs `inline` sequentially on this thread.
 */
export async function parallelMap<T, R>(
  items: T[],
  inline: (item: T, index: number) => R,
  spec?: WorkerSpec<T, R>,
  opts: ParallelOptions = {},
): Promise<R[]> {
  const total = items.length;
  const poolSize = Math.min(opts.maxWorkers ?? hwConcurrency(), total);

  // FALLBACK: no spec, no Worker support, or single core → run inline.
  if (!spec || !workersAvailable() || poolSize <= 1) {
    const out: R[] = new Array(total);
    for (let i = 0; i < total; i++) {
      out[i] = inline(items[i], i);
      opts.onTick?.(i + 1, total);
      // Yield so a UI gauge can paint between heavy items.
      if (typeof queueMicrotask === 'function') await Promise.resolve();
    }
    return out;
  }

  try {
    return await runPool(items, spec, poolSize, opts, total);
  } catch {
    // Worker construction/exec failed at runtime → degrade to inline.
    const out: R[] = new Array(total);
    for (let i = 0; i < total; i++) {
      out[i] = inline(items[i], i);
      opts.onTick?.(i + 1, total);
    }
    return out;
  }
}

async function runPool<T, R>(
  items: T[],
  spec: WorkerSpec<T, R>,
  poolSize: number,
  opts: ParallelOptions,
  total: number,
): Promise<R[]> {
  const out: R[] = new Array(total);
  let next = 0;
  let completed = 0;
  const workers = Array.from({ length: poolSize }, () => new Worker(spec.url, { type: 'module' }));

  // Optional one-time init (e.g. SRS for MSM): post to each worker, await ready.
  if (spec.initMessage !== undefined) {
    await Promise.all(
      workers.map(
        (w) =>
          new Promise<void>((res, rej) => {
            w.onmessage = () => res();
            w.onerror = (e) => rej(e);
            w.postMessage(spec.initMessage);
          }),
      ),
    );
  }

  await new Promise<void>((resolve, reject) => {
    let active = workers.length;
    const dispatch = (w: Worker) => {
      if (next >= total) {
        w.terminate();
        if (--active === 0) resolve();
        return;
      }
      const idx = next++;
      w.onmessage = (e: MessageEvent) => {
        out[idx] = spec.fromMessage(e.data);
        opts.onTick?.(++completed, total);
        dispatch(w);
      };
      w.onerror = (e) => reject(e);
      w.postMessage(spec.toMessage(items[idx], idx));
    };
    for (const w of workers) dispatch(w);
  });
  return out;
}

/**
 * Persistent Web Worker pool: spawns its workers (and runs the one-time init) ONCE,
 * then serves many `map` batches without respawning or reloading the worker module.
 * The prover runs several embarrassingly-parallel stages (3 coset maps + commits),
 * so reusing one pool across them avoids paying worker spawn + module-load + SRS-init
 * on every stage. `available()` is false (→ caller runs inline) when there is no
 * `Worker` (Node) or only one usable core.
 */
export class WorkerPool {
  private readonly workers: Worker[];
  private readonly ready: Promise<void>;
  private readonly usable: boolean;

  constructor(url: URL, size: number, initMessage?: unknown) {
    this.usable = workersAvailable() && size > 1;
    if (!this.usable) {
      this.workers = [];
      this.ready = Promise.resolve();
      return;
    }
    this.workers = Array.from({ length: size }, () => new Worker(url, { type: 'module' }));
    this.ready =
      initMessage === undefined
        ? Promise.resolve()
        : Promise.all(
            this.workers.map(
              (w) =>
                new Promise<void>((res, rej) => {
                  w.onmessage = () => res();
                  w.onerror = (e) => rej(e);
                  w.postMessage(initMessage);
                }),
            ),
          ).then(() => undefined);
  }

  available(): boolean {
    return this.usable;
  }

  /** Map `items` over the pooled workers (or `inline` if the pool is not usable). */
  async map<T, R>(
    items: T[],
    inline: (item: T, index: number) => R,
    toMessage: (item: T, index: number) => unknown,
    fromMessage: (msg: unknown) => R,
    onTick?: (done: number, total: number) => void,
  ): Promise<R[]> {
    const total = items.length;
    if (!this.usable) {
      const out: R[] = new Array(total);
      for (let i = 0; i < total; i++) {
        out[i] = inline(items[i], i);
        onTick?.(i + 1, total);
      }
      return out;
    }
    await this.ready;
    const pool = this.workers.slice(0, Math.min(this.workers.length, total));
    const out: R[] = new Array(total);
    let next = 0;
    let completed = 0;
    await new Promise<void>((resolve, reject) => {
      let active = pool.length;
      const dispatch = (w: Worker): void => {
        if (next >= total) {
          if (--active === 0) resolve();
          return;
        }
        const idx = next++;
        w.onmessage = (e: MessageEvent): void => {
          out[idx] = fromMessage(e.data);
          onTick?.(++completed, total);
          dispatch(w);
        };
        w.onerror = (e): void => reject(e);
        w.postMessage(toMessage(items[idx], idx));
      };
      for (const w of pool) dispatch(w);
    });
    return out;
  }

  terminate(): void {
    for (const w of this.workers) w.terminate();
  }
}
