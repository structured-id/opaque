/**
 * Platform capability detection + ZKPP kernel auto-selection.
 *
 * Kernel tiers (fastest → slowest):
 *   wasm-simd-threaded  — SIMD128 + worker-pool threads (needs cross-origin isolation)
 *   wasm-simd           — SIMD128, single-thread
 *   wasm-threaded       — no SIMD, worker-pool threads
 *   wasm                — baseline single-thread WASM
 *   ts                  — pure-TS BigInt fallback (no WASM at all) — ~50-100x slower
 *
 * The library probes the platform once and loads the best kernel available.
 */

export interface Capabilities {
  /** WebAssembly is available at all. */
  wasm: boolean;
  /** WASM fixed-width SIMD (128-bit) is supported. */
  simd128: boolean;
  /** Shared-memory threads usable (SharedArrayBuffer + cross-origin isolation). */
  threads: boolean;
}

export type Kernel = 'wasm-simd-threaded' | 'wasm-simd' | 'wasm-threaded' | 'wasm' | 'ts';

// Canonical WASM-SIMD probe module (contains a v128 op): WebAssembly.validate
// returns true only if the runtime understands SIMD128. From wasm-feature-detect.
const SIMD_PROBE = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 10, 1, 8, 0, 65, 0, 253,
  15, 253, 98, 11,
]);

export function detectCapabilities(): Capabilities {
  const wasm =
    typeof WebAssembly === 'object' &&
    typeof WebAssembly.validate === 'function' &&
    typeof WebAssembly.instantiate === 'function';

  let simd128 = false;
  if (wasm) {
    try {
      simd128 = WebAssembly.validate(SIMD_PROBE);
    } catch {
      simd128 = false;
    }
  }

  // Threads need SharedArrayBuffer. In browsers that additionally requires the
  // page to be cross-origin isolated (COOP+COEP); `crossOriginIsolated` is the
  // gate there. In Node it is undefined and SAB is always usable.
  const coi = (globalThis as { crossOriginIsolated?: boolean }).crossOriginIsolated;
  const threads = typeof SharedArrayBuffer !== 'undefined' && (coi === undefined || coi === true);

  return { wasm, simd128, threads };
}

/** Pick the fastest kernel the platform can run. */
export function selectKernel(c: Capabilities = detectCapabilities()): Kernel {
  if (!c.wasm) return 'ts';
  if (c.simd128 && c.threads) return 'wasm-simd-threaded';
  if (c.simd128) return 'wasm-simd';
  if (c.threads) return 'wasm-threaded';
  return 'wasm';
}
