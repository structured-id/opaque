// Pallas curve ops + encoding verified against pasta_curves reference vectors
// (sid-pake-core/tests/interop_vectors.rs).
import { describe, it, expect } from 'vitest';
import { GENERATOR, double, add, scalarMul, toBytes, isOnCurve, neg } from '../src/zkpp/curve.js';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

const PALLAS_GEN = '00000000ed302d991bf94c09fc98462200000000000000000000000000000040';
const PALLAS_2G = '030000b067c50313fcac1144eee2fe0e0000000000000000000000000000001c';
const PALLAS_12345G = 'a8d43ad4fa53e9f23a4612cba9981697c35a99b1e481c58f6b444d9d9dedf529';
const PALLAS_ID = '00'.repeat(32);

describe('Pallas curve — pasta_curves interop', () => {
  it('generator (−1, 2) is on curve and encodes to PALLAS_GEN', () => {
    expect(isOnCurve(GENERATOR)).toBe(true);
    expect(hex(toBytes(GENERATOR))).toBe(PALLAS_GEN);
  });

  it('2·G via double() matches PALLAS_2G', () => {
    const g2 = double(GENERATOR);
    expect(isOnCurve(g2)).toBe(true);
    expect(hex(toBytes(g2))).toBe(PALLAS_2G);
  });

  it('2·G via add(G,G) equals double(G)', () => {
    expect(hex(toBytes(add(GENERATOR, GENERATOR)))).toBe(PALLAS_2G);
  });

  it('12345·G via scalarMul matches PALLAS_12345G', () => {
    const p = scalarMul(12345n, GENERATOR);
    expect(isOnCurve(p)).toBe(true);
    expect(hex(toBytes(p))).toBe(PALLAS_12345G);
  });

  it('identity encodes to all zeros', () => {
    expect(hex(toBytes(null))).toBe(PALLAS_ID);
  });

  it('add(P, -P) = identity', () => {
    const p = scalarMul(777n, GENERATOR);
    expect(toBytes(add(p, neg(p)))).toEqual(new Uint8Array(32));
  });
});
