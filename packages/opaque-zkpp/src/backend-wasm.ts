/**
 * WASM ZKPP backend. The kernel tier selects the compiled artifact: SIMD128 build
 * for `wasm-simd*`, baseline build otherwise; threaded tiers initialise the
 * rayon worker pool (requires a cross-origin-isolated page: COOP+COEP). Kept
 * separate from the pure-TS backend so each is its own lazy chunk.
 */
import type { Kernel } from './capabilities.js';
import type { ZkppProver, ProveOptions } from './loader.js';

interface WasmModule {
  default: (moduleOrPath?: unknown) => Promise<unknown>;
  initThreadPool?: (n: number) => Promise<void>;
  generate_zkpp_proof: (
    password: string,
    policyVersion: number,
    mode: string,
    prevCommitment: string | null,
  ) => string;
}

// CE default policy version (matches CE_DEFAULT_POLICY used by the pure-TS path).
const CE_POLICY_VERSION = 1;

// Instantiate (and, for threaded tiers, thread-pool) each wasm variant exactly
// once — `default()` and `initThreadPool()` must not run twice per module.
const loaded = new Map<string, Promise<WasmModule>>();
function loadWasm(simd: boolean, threaded: boolean): Promise<WasmModule> {
  const key = simd ? 'simd' : 'base';
  let p = loaded.get(key);
  if (!p) {
    p = (async (): Promise<WasmModule> => {
      // wasm/ ships at the package root (sibling of src/ and dist/), so '../wasm/'
      // resolves both at build (from src/) and at runtime (from dist/). These two
      // paths are marked external in tsup.config.ts so esbuild leaves the wasm glue
      // (and its rayon worker) untouched as a runtime import.
      const mod = (await import(
        simd ? '../wasm/opaque-simd.js' : '../wasm/opaque.js'
      )) as WasmModule;
      await mod.default();
      if (threaded && typeof mod.initThreadPool === 'function') {
        await mod.initThreadPool(navigator.hardwareConcurrency ?? 4);
      }
      return mod;
    })();
    loaded.set(key, p);
  }
  return p;
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function createWasmProver(kernel: Kernel): ZkppProver {
  const simd = kernel === 'wasm-simd-threaded' || kernel === 'wasm-simd';
  const threaded = kernel === 'wasm-simd-threaded' || kernel === 'wasm-threaded';
  return {
    kernel,
    async proveRegistration(password: string, opts: ProveOptions = {}): Promise<Uint8Array> {
      // WASM proves in one call; report coarse start→done so the gauge moves.
      // (Sector binding via `opts.context` is an OPAQUE/Okamoto-layer concern, not
      // bound into the SNARK here — the pure-TS path likewise ignores context.)
      opts.onProgress?.({ stage: 'witness', fraction: 0, label: 'Proving (WASM)' });
      const mod = await loadWasm(simd, threaded);
      const json = mod.generate_zkpp_proof(password, CE_POLICY_VERSION, 'registration', null);
      const { proof } = JSON.parse(json) as { proof: string };
      opts.onProgress?.({ stage: 'ipa', fraction: 1, label: 'Done' });
      return base64ToBytes(proof);
    },
  };
}
