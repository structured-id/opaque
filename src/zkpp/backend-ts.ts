/**
 * Pure-TS ZKPP backend (no-WASM fallback). This module — and everything it imports
 * (the full halo2 IPA prover + circuit gadgets) — is loaded only via the loader's
 * dynamic import when no WASM kernel is available, so it never ships on the hot path.
 */
import type { ZkppProver } from './loader.js';
import { proveRegistrationTs } from './zkpp-prove.js';

export function createTsProver(): ZkppProver {
  return {
    kernel: 'ts',
    async proveRegistration(password, context) {
      return proveRegistrationTs(password, context ?? new Uint8Array());
    },
  };
}
