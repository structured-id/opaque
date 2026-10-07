/**
 * Platform capability detection + ZKPP kernel auto-selection.
 *
 * Kernel tiers (fastest → slowest):
 *   wasm-simd-threaded  — SIMD128 + worker-pool threads
 *   wasm-threaded       — no SIMD, worker-pool threads
 *   ts-threaded         — pure-TS BigInt + Web Worker pool (no WASM, multi-core)
 *   ts                  — pure-TS BigInt, single-thread (no WASM, no workers), slowest
 *
 * The WASM tiers come from a separately distributed kernel (see kernel.ts).
 * Its artifacts import shared memory and spawn Web Workers for their thread
 * pool, so they need SharedArrayBuffer (cross-origin isolation in browsers:
 * COOP+COEP) and the Worker constructor; without either no WASM tier loads.
 * Node has the buffer but no Web Workers, so it gets the single-thread TS tier.
 */
import { registeredZkppKernel } from "./kernel.js";

export interface Capabilities {
  /** WebAssembly is available at all. */
  wasm: boolean;
  /** WASM fixed-width SIMD (128-bit) is supported. */
  simd128: boolean;
  /** Shared-memory threads usable (SharedArrayBuffer + cross-origin isolation). */
  threads: boolean;
  /** Web Workers exist, so the TS prover runs off the calling thread. */
  workers: boolean;
}

/** The tiers a native WebAssembly kernel serves. */
export type WasmKernel = "wasm-simd-threaded" | "wasm-threaded";

/** The tiers this package serves itself. */
export type TsKernel = "ts-threaded" | "ts";

export type Kernel = WasmKernel | TsKernel;

export function isWasmKernel(k: Kernel): k is WasmKernel {
  return k === "wasm-simd-threaded" || k === "wasm-threaded";
}

// Canonical WASM-SIMD probe module (contains a v128 op): WebAssembly.validate
// returns true only if the runtime understands SIMD128. From wasm-feature-detect.
const SIMD_PROBE = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 10, 1, 8,
  0, 65, 0, 253, 15, 253, 98, 11,
]);

export function detectCapabilities(): Capabilities {
  const wasm =
    typeof WebAssembly === "object" &&
    typeof WebAssembly.validate === "function" &&
    typeof WebAssembly.instantiate === "function";

  let simd128 = false;
  if (wasm) {
    try {
      simd128 = WebAssembly.validate(SIMD_PROBE);
    } catch {
      simd128 = false;
    }
  }

  // Threads mean the WASM artifacts can run: they import shared memory and
  // spawn Web Workers for their rayon pool, so SharedArrayBuffer and the
  // Worker constructor are both required. In browsers the buffer additionally
  // requires a cross-origin-isolated page (COOP+COEP); `crossOriginIsolated`
  // is the gate there. Node has the buffer but no Web Workers, so it never
  // gets a WASM tier.
  const coi = (globalThis as { crossOriginIsolated?: boolean })
    .crossOriginIsolated;
  const threads =
    typeof SharedArrayBuffer !== "undefined" &&
    typeof Worker !== "undefined" &&
    (coi === undefined || coi === true);

  // The TS prover pool is Web Workers, which need no SharedArrayBuffer or
  // cross-origin isolation (data moves by structured clone). Node has none, so
  // its prover runs on the calling thread and the kernel reports exactly that.
  const workers = typeof Worker !== "undefined";

  return { wasm, simd128, threads, workers };
}

/**
 * Pick the fastest kernel the platform can run; a WASM tier only when a
 * native kernel is registered.
 */
export function selectKernel(
  c: Capabilities = detectCapabilities(),
  nativeKernel: boolean = registeredZkppKernel() !== undefined,
): Kernel {
  if (nativeKernel && c.wasm && c.threads)
    return c.simd128 ? "wasm-simd-threaded" : "wasm-threaded";
  return selectTsKernel(c);
}

/** The fastest of this package's own TypeScript tiers the platform runs. */
export function selectTsKernel(c: Capabilities): TsKernel {
  return c.workers ? "ts-threaded" : "ts";
}
