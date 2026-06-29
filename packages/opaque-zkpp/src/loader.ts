/**
 * Dynamic ZKPP prover loader. Picks the fastest available kernel and lazy-imports
 * ONLY that backend, in priority order: wasm-simd(+threads) → wasm → pure-TS.
 *
 * The pure-TS prover (large: field/curve/Poseidon/FFT/IPA/circuit) lives behind a
 * dynamic `import('./backend-ts.js')`, so a bundler code-splits it into a separate
 * chunk that is fetched ONLY when no WASM is available. When WASM works, the TS
 * fallback code is never downloaded or parsed.
 */
import { selectKernel, type Kernel } from "./capabilities.js";
import type { ZkppProgress } from "./progress.js";

export interface ProveOptions {
  /** Optional binding context (sector / origin) mixed into the proof. */
  context?: Uint8Array;
  /** Progress callback for a UI gauge: fires with monotonic `fraction` 0..1. */
  onProgress?: (p: ZkppProgress) => void;
}

export interface ZkppProver {
  readonly kernel: Kernel;
  /** Generate the ZKPP registration proof for a password. `opts.onProgress` drives a gauge. */
  proveRegistration(password: string, opts?: ProveOptions): Promise<Uint8Array>;
}

export async function loadZkppProver(
  kernel: Kernel = selectKernel(),
): Promise<ZkppProver> {
  if (kernel === "ts" || kernel === "ts-threaded") {
    // Fallback only: this dynamic import is the pure-TS chunk. 'ts-threaded' runs
    // the embarrassingly-parallel stages on a Web Worker / worker_threads pool.
    const ts = await import("./backend-ts.js");
    return ts.createTsProver(kernel === "ts-threaded");
  }
  // WASM kernels: load the matching compiled module (simd128 vs baseline).
  const wasm = await import("./backend-wasm.js");
  return wasm.createWasmProver(kernel);
}
