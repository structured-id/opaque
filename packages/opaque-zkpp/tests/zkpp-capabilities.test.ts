import { describe, it, expect } from 'vitest';
import { detectCapabilities, selectKernel, type Capabilities } from '../src/capabilities.js';

describe('ZKPP kernel auto-selection', () => {
  it('detects WASM + SIMD128 in the test runtime (Node)', () => {
    const c = detectCapabilities();
    expect(c.wasm).toBe(true);
    expect(c.simd128).toBe(true); // Node ≥16 supports WASM SIMD
  });

  it('selectKernel picks the fastest available tier', () => {
    const k = (o: Partial<Capabilities>): string =>
      selectKernel({ wasm: true, simd128: false, threads: false, ...o });
    expect(k({ simd128: true, threads: true })).toBe('wasm-simd-threaded');
    expect(k({ simd128: true, threads: false })).toBe('wasm-simd');
    expect(k({ simd128: false, threads: true })).toBe('wasm-threaded');
    expect(k({ simd128: false, threads: false })).toBe('wasm');
  });

  it('falls back to pure-TS when WASM is unavailable', () => {
    expect(selectKernel({ wasm: false, simd128: false, threads: false })).toBe('ts');
    // even if other flags somehow set, no WASM ⇒ ts
    expect(selectKernel({ wasm: false, simd128: true, threads: true })).toBe('ts');
  });
});
