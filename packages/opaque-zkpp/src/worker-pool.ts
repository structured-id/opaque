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
