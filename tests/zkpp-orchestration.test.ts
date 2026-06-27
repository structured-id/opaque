// Synthesize orchestration: each gadget/chip region placed into the real ZkppCircuit
// advice columns must reproduce the full-circuit advice dump byte-exact.
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/zkpp/field.js';
import { gadgetAWitness, type PolicyParams } from '../src/zkpp/circuit/gadget-a.js';
import gaPlaced from './fixtures/zkpp-gadget-a-placed.json';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));
const CE: PolicyParams = { minLength: 8, minUpper: 1, minLower: 1, minDigit: 1, minSymbol: 0 };

describe('synthesize orchestration — region R0 (gadget A policy engine)', () => {
  it('gadget_a witness reproduces full-circuit advice cols 0-9 (rows 0-127) byte-exact', () => {
    const pw = [...new TextEncoder().encode('Str0ngP@ss')];
    const w = gadgetAWitness(pw, CE);
    // Column order from PolicyEngineChip::configure: byte, active, isU, isL, isD, isS,
    // accU, accL, accD, accS.
    const myCols = [w.byte, w.active, w.isU, w.isL, w.isD, w.isS, w.accU, w.accL, w.accD, w.accS];
    for (let c = 0; c < 10; c++) {
      const got = myCols[c].map((v) => fe(BigInt(v)));
      expect(got).toEqual(gaPlaced.cols[c]);
    }
  });
});
