// Gadget C opaque-binder application witness: H_p = HashToCurve(pw), M = blind·H_p.
// (The ECC in-circuit chip cells for the variable-base mul are a separate port.)
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/field.js';
import { hashToCurveOutside } from '../src/hash-to-curve.js';
import { Pallas } from '../src/curve.js';
import gc from './fixtures/gadget-c.json';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));
const leHex = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};

describe('gadget C opaque-binder application witness — halo2 interop', () => {
  it('H_p = HashToCurve(Str0ngP@ss) and M = 7·H_p match gadget_c', () => {
    const pw = new TextEncoder().encode('Str0ngP@ss');
    const { point } = hashToCurveOutside(pw);
    expect(fe(point.x)).toBe(gc.hpx);
    expect(fe(point.y)).toBe(gc.hpy);
    const M = Pallas.scalarMul(leHex(gc.blind), point) as { x: bigint; y: bigint };
    expect(fe(M.x)).toBe(gc.mx);
    expect(fe(M.y)).toBe(gc.my);
  });
});
