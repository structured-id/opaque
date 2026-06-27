/**
 * WASM ZKPP backend. The kernel tier selects the compiled artifact: SIMD128 build
 * for `wasm-simd*`, baseline build otherwise; threaded tiers initialise the worker
 * pool. Kept separate from the pure-TS backend so each is its own lazy chunk.
 */
import type { Kernel } from './capabilities.js';
import type { ZkppProver } from './loader.js';

export function createWasmProver(kernel: Kernel): ZkppProver {
  const simd = kernel === 'wasm-simd-threaded' || kernel === 'wasm-simd';
  const threaded = kernel === 'wasm-simd-threaded' || kernel === 'wasm-threaded';
  return {
    kernel,
    async proveRegistration(password, context) {
      // Lazy-load the matching wasm glue (simd128 or baseline); threaded tiers
      // additionally spin up the rayon worker pool before proving.
      const mod = await import(simd ? './wasm/opaque-simd.js' : './wasm/opaque.js');
      if (threaded && typeof mod.initThreadPool === 'function') {
        await mod.initThreadPool(navigator.hardwareConcurrency ?? 4);
      }
      return mod.generate_zkpp_proof(password, context ?? new Uint8Array());
    },
  };
}
