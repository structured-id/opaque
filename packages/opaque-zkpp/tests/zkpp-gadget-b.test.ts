// Gadget B diff-accumulator witness interop vs sid-pake-core gadget_b (registration).
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/field.js';
import { gadgetBDiffAcc } from '../src/circuit/gadget-b.js';
import gb from './fixtures/gadget-b.json';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));

describe('gadget B history-nullifier diff-accumulator — halo2 interop', () => {
  it('Str0ngP@ss diff/acc/diffInv match gadget_b (p_old=0)', () => {
    const pn = [...new TextEncoder().encode('Str0ngP@ss')].map((b) => BigInt(b));
    const w = gadgetBDiffAcc(pn, []);
    expect(w.diff.map(fe)).toEqual(gb.diff);
    expect(w.acc.map(fe)).toEqual(gb.accs);
    expect(fe(w.finalAcc)).toBe(gb.acc);
    expect(fe(w.diffInv)).toBe(gb.diffinv);
  });
});
