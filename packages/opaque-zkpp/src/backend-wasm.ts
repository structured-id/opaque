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
    async proveRegistration(password, opts = {}) {
      // Lazy-load the matching wasm glue (simd128 or baseline); threaded tiers
      // additionally spin up the rayon worker pool before proving.
      opts.onProgress?.({ stage: 'witness', fraction: 0, label: 'Proving (WASM)' });
      const mod = await import(simd ? './wasm/opaque-simd.js' : './wasm/opaque.js');
      if (threaded && typeof mod.initThreadPool === 'function') {
        await mod.initThreadPool(navigator.hardwareConcurrency ?? 4);
      }
      // WASM proves in one opaque call; fine-grained progress needs a wasm-bindgen
      // progress callback (follow-up). Report coarse start→done so the gauge moves.
      const proof = mod.generate_zkpp_proof(password, opts.context ?? new Uint8Array());
      opts.onProgress?.({ stage: 'ipa', fraction: 1, label: 'Done' });
      return proof;
    },
  };
}
