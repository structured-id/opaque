// Gadget A (policy engine) witness interop vs sid-pake-core gadget_a (dump_gadget_a_witness).
import { describe, it, expect } from 'vitest';
import { gadgetAWitness, type PolicyParams } from '../src/circuit/gadget-a.js';
import ga from './fixtures/gadget-a.json';

const CE: PolicyParams = { minLength: 8, minUpper: 1, minLower: 1, minDigit: 1, minSymbol: 0 };

describe('gadget A policy-engine witness — halo2 interop', () => {
  it('Str0ngP@ss witness (byte/active/flags/acc + compliance) matches gadget_a', () => {
    const pw = [...new TextEncoder().encode('Str0ngP@ss')];
    const w = gadgetAWitness(pw, CE);
    expect(w.compliant).toBe(ga.compliant === 1);
    expect(w.final).toEqual(ga.final);
    // Every row: [byte, active, isU, isL, isD, isS, accU, accL, accD, accS].
    const rows = w.byte.map((_, i) => [
      w.byte[i], w.active[i], w.isU[i], w.isL[i], w.isD[i], w.isS[i],
      w.accU[i], w.accL[i], w.accD[i], w.accS[i],
    ]);
    expect(rows).toEqual(ga.rows);
  });
});
