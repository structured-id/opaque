/**
 * Dynamic ZKPP prover loader. Picks the fastest available kernel and lazy-imports
 * ONLY that backend, in priority order: wasm-simd(+threads) → wasm → pure-TS.
 *
 * The pure-TS prover (large: field/curve/Poseidon/FFT/IPA/circuit) lives behind a
 * dynamic `import('./backend-ts.js')`, so a bundler code-splits it into a separate
 * chunk that is fetched ONLY when no WASM is available. When WASM works, the TS
 * fallback code is never downloaded or parsed.
 */
import { selectKernel, type Kernel } from './capabilities.js';

export interface ZkppProver {
  readonly kernel: Kernel;
  /** Generate the ZKPP registration proof for a password (+ optional context). */
  proveRegistration(password: string, context?: Uint8Array): Promise<Uint8Array>;
}

export async function loadZkppProver(kernel: Kernel = selectKernel()): Promise<ZkppProver> {
  if (kernel === 'ts') {
    // Fallback only: this dynamic import is the pure-TS chunk.
    const ts = await import('./backend-ts.js');
    return ts.createTsProver();
  }
  // WASM kernels: load the matching compiled module (simd128 vs baseline).
  const wasm = await import('./backend-wasm.js');
  return wasm.createWasmProver(kernel);
}
