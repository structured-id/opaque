// NTT interop vs halo2 best_fft. Vector from interop_vectors.rs (dump_fft).
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/field.js';
import { bestFft, omegaForSize } from '../src/fft.js';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));

const FFT_OMEGA8 = 'aec58a704e07151dac23f21b51fb3bc7d95ee63d120163d229a76d0cc61c8f3f';
const FFT_OUT = [
  '2400000000000000000000000000000000000000000000000000000000000000',
  '9cc22c2cd24eccad70c6704c568546a0383bfbe5a912680b7f51d9c250479b1c',
  '9424c99c91f194e3aa34500d07e3b98a88f5657323c12e3a83285dc313ce0825',
  '6d799af29b9ccf7f36561d3b445819ad27502fff62900a9778001f3c29ab8912',
  'fdffffffec302d991bf94c09fc98462200000000000000000000000000000040',
  '8c86650d51945d19e5a22fceb7402d75d8afd0009d6ff56887ffe0c3d654762d',
  '65db36635b3f98b570c4fcfbf4b58c97770a9a8cdc3ed1c57cd7a23cec31f71a',
  '5d3dd3d31ae260ebaa32dcbca5130082c7c4041a56ed97f480ae263dafb86423',
];

describe('NTT — halo2 best_fft interop', () => {
  it('omegaForSize(3) is the 8th root of unity (matches Rust)', () => {
    expect(fe(omegaForSize(3))).toBe(FFT_OMEGA8);
  });

  it('bestFft([1..8]) matches halo2 best_fft output', () => {
    const a = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n];
    bestFft(a, omegaForSize(3), 3);
    expect(a.map(fe)).toEqual(FFT_OUT);
  });

  it('FFT[0] equals the sum of inputs (DC term)', () => {
    const a = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n];
    bestFft(a, omegaForSize(3), 3);
    expect(a[0]).toBe(36n);
  });
});
