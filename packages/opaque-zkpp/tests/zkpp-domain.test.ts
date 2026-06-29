// EvaluationDomain coset-FFT interop vs halo2 coeff_to_extended. Vector from
// interop_vectors.rs (dump_domain): k=2, j=4 ⇒ extended_k=4 (16), poly [1,2,3,4].
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/field.js';
import {
  coeffToExtended,
  lagrangeToCoeff,
  extendedToCoeff,
  divideByVanishing,
  vanishingTInv,
} from '../src/domain.js';
import { bestFft, omegaForSize } from '../src/fft.js';
import toyH from './fixtures/toy-h.json';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));

const DOM_EXT = [
  '4ab501022fd27f7bd2c79fd1290d2705504e55a8232a55d38e4532b57c35332d',
  '35e7d8fbc1f5e637d2a792a1475aba451d17f27d07d8fe4ba027d1f71956d616',
  '306258731046193a5a1ef1a1b57252a535e91558e899979c0f1903d6b2f89e01',
  '35f4b451410c7ce469a66d4e89c103f08b4a37f5a189e9bfc8c47a1b53eeba03',
  'ecd855ec8f8473b4db5bb186516376865f7da2167a8b7133b43ad6f8f7c53f0b',
  '0f17eed23065407243985bce498c861be8da0edd88449a30f65fe7972334f934',
  '07120aec22ae0c88c2bbf321636fe9d9da107335e3125ddaaf5b727402e22720',
  '1ec456f75938a76912473d77f0dc827f3e502bef2c39cf49e3d805d39ce5d634',
  '5f8a080a2488f79dc9fb37fcdc76efb28f87aa49b2d2a920ca5bfb896f0b0022',
  'a789e5b18058fef5f05588da5e771866d8146f4c8c3dd75b8f6fc5a03f70ae2a',
  '43d81ff748fc0d4f3792c655696790b4c2ae4d0088ade7e01cfbd8cf5b737c2c',
  '4bd14f0bc84f61c326defe26039ef62cc5b2eceb1d608c794f0854ed57051022',
  '71e79f07f7826f64bfd210be9f4a0006c1ac5df7af778fd8f223fcc71bf98c25',
  '1b78537f66ae3492305c23c807d4337d22f98f58e3a58f27da0882cf82058209',
  '8cb37da95d712621e385eef875e8c0102d572972aca523a82390b1e5eeb1bc31',
  '6876a4ab76cdd5209426f0257bf50fa870b2b02f13ddba7c045a2b24b8265e25',
];

describe('EvaluationDomain coeff_to_extended — halo2 interop', () => {
  it('coset-FFT of [1,2,3,4] over extended_k=4 matches halo2', () => {
    const ext = coeffToExtended([1n, 2n, 3n, 4n], 4);
    expect(ext.length).toBe(16);
    expect(ext.map(fe)).toEqual(DOM_EXT);
  });

  it('lagrangeToCoeff inverts the forward NTT', () => {
    const coeff = [1n, 2n, 3n, 4n];
    const lag = [...coeff];
    bestFft(lag, omegaForSize(2), 2);
    expect(lagrangeToCoeff(lag, 2).map(fe)).toEqual(coeff.map(fe));
  });

  it('extendedToCoeff inverts coeffToExtended', () => {
    const coeff = [1n, 2n, 3n, 4n];
    const back = extendedToCoeff(coeffToExtended(coeff, 4), 2, 4, 3);
    expect(back.slice(0, 4).map(fe)).toEqual(coeff.map(fe));
  });

  it('divide_by_vanishing + extended_to_coeff: folded H → h(X) (halo2 toy)', () => {
    // k=4, extended_k=5, quotient_poly_degree=2. Vectors from vanishing construct.
    const f32 = (h: string) =>
      Array.from({ length: 32 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const hFolded = f32(toyH.h_folded);
    const divided = divideByVanishing(hFolded, vanishingTInv(4, 5));
    const hPoly = extendedToCoeff(divided, 4, 5, 2);
    expect(hPoly.map(fe)).toEqual(f32(toyH.h_poly).map(fe));
  });
});

const leHex = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2)
    v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};
