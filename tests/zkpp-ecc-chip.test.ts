// ECC incomplete double-and-add witness interop vs halo2_gadgets variable-base mul.
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/zkpp/field.js';
import { incompleteDoubleAndAdd } from '../src/zkpp/circuit/ecc-chip.js';
import ecc from './fixtures/ecc-incomplete.json';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));
const le = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};

describe('ECC variable-base mul — incomplete double-and-add witness', () => {
  it('z/λ1/λ2/x_a sequence matches halo2_gadgets', () => {
    const out = incompleteDoubleAndAdd(le(ecc.xp), le(ecc.yp), le(ecc.x0), le(ecc.y0), ecc.bits);
    const got = out.rows.map((r) => [fe(r.z), fe(r.lambda1), fe(r.lambda2), fe(r.xa)].join(':'));
    expect(got).toEqual(ecc.rows.map((r: string[]) => r.join(':')));
  });
});
