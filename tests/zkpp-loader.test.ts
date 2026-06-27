// Kernel selection priority for the dynamic loader (wasm-simd+threads → ... → ts).
import { describe, it, expect } from 'vitest';
import { selectKernel, type Capabilities } from '../src/zkpp/capabilities.js';

const cap = (wasm: boolean, simd128: boolean, threads: boolean): Capabilities => ({ wasm, simd128, threads });

describe('ZKPP kernel selection priority', () => {
  it('prefers wasm-simd-threaded, falls through to pure ts', () => {
    expect(selectKernel(cap(true, true, true))).toBe('wasm-simd-threaded');
    expect(selectKernel(cap(true, true, false))).toBe('wasm-simd');
    expect(selectKernel(cap(true, false, true))).toBe('wasm-threaded');
    expect(selectKernel(cap(true, false, false))).toBe('wasm');
    expect(selectKernel(cap(false, false, false))).toBe('ts');
    expect(selectKernel(cap(false, true, true))).toBe('ts'); // no wasm → ts regardless
  });
});
