// Vesta curve (IPA commitment curve) interop vs pasta_curves. Vector from
// interop_vectors.rs (dump_vesta).
import { describe, it, expect } from 'vitest';
import { Vesta } from '../src/curve.js';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

const VESTA_GEN = '0000000021eb468cdda89409fc98462200000000000000000000000000000040';
const VESTA_2G = '03000070de065fede0093144eee2fe0e0000000000000000000000000000001c';
const VESTA_12345G = '7de0561ce03e0a7920142943f7683f20e26b8a2736e0b5b3de552fbf17f3632e';

describe('Vesta curve — pasta_curves interop', () => {
  it('generator (−1, 2) over Fq encodes to VESTA_GEN', () => {
    expect(Vesta.isOnCurve(Vesta.GENERATOR)).toBe(true);
    expect(hex(Vesta.toBytes(Vesta.GENERATOR))).toBe(VESTA_GEN);
  });

  it('2·G matches VESTA_2G', () => {
    expect(hex(Vesta.toBytes(Vesta.double(Vesta.GENERATOR)))).toBe(VESTA_2G);
  });

  it('12345·G matches VESTA_12345G', () => {
    expect(hex(Vesta.toBytes(Vesta.scalarMul(12345n, Vesta.GENERATOR)))).toBe(VESTA_12345G);
  });

  it('msm([2,3],[G,G]) == 5·G', () => {
    const viaMsm = Vesta.msm([2n, 3n], [Vesta.GENERATOR, Vesta.GENERATOR]);
    const via5g = Vesta.scalarMul(5n, Vesta.GENERATOR);
    expect(hex(Vesta.toBytes(viaMsm))).toBe(hex(Vesta.toBytes(via5g)));
  });
});
