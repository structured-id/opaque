/**
 * The page side of the TypeScript prover. Starts the prover worker and the
 * lanes, hands the lanes' ports to the worker, and follows the tab's
 * visibility: a hidden tab gets a small CPU budget for the whole page, so the
 * host lets one lane compute there and every lane again once the tab shows.
 * Where Web Workers do not exist, the same core proves on the calling thread.
 */
import {
  ProverCore,
  type CoreProgress,
  type ProveJob,
  type ProveResult,
} from "./prover-core.js";
import type { HostMessage, WorkerMessage } from "./protocol.js";
import { secureRandom } from "../random.js";
import { openKeyStore } from "./key-store.js";

/** Lanes allowed to compute while the tab is hidden. */
const HIDDEN_LANES = 1;

export interface ProverHostOptions {
  /** Prove on the calling thread and start no worker, even where they exist. */
  local?: boolean;
  /** Lane count; defaults to the logical cores, at most 8 (the coset classes). */
  lanes?: number;
  /** Start the prover worker (default: the package's `prover-worker.js`). */
  spawnProver?: () => Worker;
  /** Start one lane (default: the package's `lane-worker.js`). */
  spawnLane?: () => Worker;
}

// The workers this package ships next to its entry module. Bundlers (Vite,
// webpack 5, Parcel) emit a worker only when the URL is a string literal
// inside `new Worker(new URL(..., import.meta.url))`.
const packagedProver = () =>
  new Worker(new URL("./prover-worker.js", import.meta.url), {
    type: "module",
  });
const packagedLane = () =>
  new Worker(new URL("./lane-worker.js", import.meta.url), { type: "module" });

export interface Prover {
  prepare(
    policyVersion: number,
    historyDomains: number,
    onProgress?: CoreProgress,
  ): Promise<void>;
  prove(job: ProveJob, onProgress?: CoreProgress): Promise<ProveResult>;
  close(): void;
  /** True once the prover answers no more calls (one of its workers stopped). */
  readonly stopped: boolean;
}

class WorkerProver implements Prover {
  private next = 1;
  private readonly calls = new Map<
    number,
    {
      resolve: (r: ProveResult | null) => void;
      reject: (e: Error) => void;
      onProgress?: CoreProgress;
    }
  >();
  private readonly worker: Worker;
  private readonly lanes: Worker[];
  private readonly onVisibility: () => void;
  /** Why the prover stopped; every call fails with it from then on. */
  private stoppedBy: Error | undefined;

  constructor(opts: ProverHostOptions) {
    const cores =
      typeof navigator !== "undefined" ? navigator.hardwareConcurrency : 4;
    const count = Math.max(1, Math.min(8, opts.lanes ?? cores ?? 4));
    this.worker = (opts.spawnProver ?? packagedProver)();
    this.worker.onmessage = (e) => this.receive(e.data as WorkerMessage);
    const spawnLane = opts.spawnLane ?? packagedLane;
    this.lanes = Array.from({ length: count }, spawnLane);
    // A worker whose script never runs, or that throws uncaught, reports only
    // an error event; a lane's reaches only this page, not the prover worker
    // holding its port. Either leaves the prover without answers for good.
    for (const [name, w] of [
      ["prover", this.worker],
      ...this.lanes.map((l, i) => [`lane ${i}`, l] as const),
    ] as const) {
      w.onerror = (e) =>
        this.stop(
          new Error(`ZKPP ${name} worker failed: ${e.message || "error"}`),
        );
      w.onmessageerror = () =>
        this.stop(new Error(`ZKPP ${name} worker message could not be read`));
    }
    const ports = this.lanes.map((lane) => {
      const channel = new MessageChannel();
      lane.postMessage({ port: channel.port1 }, [channel.port1]);
      return channel.port2;
    });
    this.post({ t: "init", ports }, ports);
    this.onVisibility = () =>
      this.post({
        t: "active",
        lanes: document.visibilityState === "hidden" ? HIDDEN_LANES : count,
      });
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", this.onVisibility);
      this.onVisibility();
    }
  }

  private post(m: HostMessage, transfer: Transferable[] = []): void {
    this.worker.postMessage(m, transfer);
  }

  private receive(m: WorkerMessage): void {
    const call = this.calls.get(m.id);
    if (!call) return;
    if (m.t === "progress") {
      call.onProgress?.(m.stage, m.fraction);
      return;
    }
    this.calls.delete(m.id);
    if (m.t === "done") call.resolve(m.result);
    else call.reject(new Error(m.message));
  }

  get stopped(): boolean {
    return this.stoppedBy !== undefined;
  }

  /**
   * Stop for good with `err`: pending and later calls fail with the first
   * cause, and every worker is ended.
   */
  private stop(err: Error): void {
    if (this.stoppedBy === undefined) {
      this.stoppedBy = err;
      this.release();
    }
    for (const c of this.calls.values()) c.reject(this.stoppedBy);
    this.calls.clear();
  }

  /** End the workers and the visibility listener. */
  private release(): void {
    if (typeof document !== "undefined")
      document.removeEventListener("visibilitychange", this.onVisibility);
    this.worker.terminate();
    for (const l of this.lanes) l.terminate();
  }

  private request(
    m: (id: number) => HostMessage,
    onProgress?: CoreProgress,
  ): Promise<ProveResult | null> {
    if (this.stoppedBy) return Promise.reject(this.stoppedBy);
    const id = this.next++;
    return new Promise((resolve, reject) => {
      this.calls.set(id, { resolve, reject, onProgress });
      this.post(m(id));
    });
  }

  async prepare(
    policyVersion: number,
    historyDomains: number,
    onProgress?: CoreProgress,
  ): Promise<void> {
    await this.request(
      (id) => ({ t: "prepare", id, policyVersion, historyDomains }),
      onProgress,
    );
  }

  async prove(job: ProveJob, onProgress?: CoreProgress): Promise<ProveResult> {
    const r = await this.request((id) => ({ t: "prove", id, job }), onProgress);
    if (r === null) throw new Error("prover worker returned no proof");
    return r;
  }

  close(): void {
    this.stop(new Error("prover closed"));
  }
}

/**
 * A prover in workers where the platform has them and `local` is not asked
 * for, else on this thread.
 */
export function createProver(opts: ProverHostOptions = {}): Prover {
  if (
    !opts.local &&
    typeof Worker !== "undefined" &&
    typeof MessageChannel !== "undefined"
  )
    return new WorkerProver(opts);
  const core = new ProverCore(undefined, secureRandom, openKeyStore());
  return {
    prepare: async (v, d, p) => void (await core.prepare(v, d, p)),
    prove: (job, p) => core.prove(job, p),
    close: () => core.close(),
    // On the calling thread there is no worker to lose.
    stopped: false,
  };
}
