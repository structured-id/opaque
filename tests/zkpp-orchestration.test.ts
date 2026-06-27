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

import { gadgetBDiffAcc } from '../src/zkpp/circuit/gadget-b.js';
import gbPlaced from './fixtures/zkpp-gadget-b-placed.json';

describe('synthesize orchestration — region R26 (gadget B diff-accumulator)', () => {
  it('gadget_b diff-acc reproduces real circuit advice cols 11-16 (rows 0-127) byte-exact', () => {
    const pwBytes = [...new TextEncoder().encode('Str0ngP@ss')];
    const pNew = Array.from({ length: 128 }, (_, i) => (i < pwBytes.length ? BigInt(pwBytes[i]) : 0n));
    const w = gadgetBDiffAcc(pNew, []);
    const Z = Array(128).fill(0n);
    // col11 p_new, col12 p_old(0), col13 diff, col14 diff_acc, col15 diff_inv(@127), col16 mode(0).
    const diffInvCol = [...Array(127).fill(0n), w.diffInv];
    const myCols = [pNew, Z, w.diff, w.acc, diffInvCol, Z];
    for (let c = 0; c < 6; c++) {
      const got = myCols[c].map((v) => fe(v));
      expect(got).toEqual(gbPlaced.cols[c]);
    }
  });
});

import { permuteWithCells } from '../src/zkpp/poseidon.js';
import pow5r5 from './fixtures/zkpp-pow5-r5.json';

describe('synthesize orchestration — region R5 (Pow5 Poseidon permutation, first gadget_b hash H(0,0))', () => {
  it('permuteWithCells([0,0,2<<64]) reproduces real circuit Pow5 cols 18-21 byte-exact', () => {
    const cells = permuteWithCells([0n, 0n, 2n << 64n]);
    expect(cells.states.map((s) => fe(s[0]))).toEqual(pow5r5.st0);
    expect(cells.states.map((s) => fe(s[1]))).toEqual(pow5r5.st1);
    expect(cells.states.map((s) => fe(s[2]))).toEqual(pow5r5.st2);
    expect(cells.partialSbox.map((v) => fe(v))).toEqual(pow5r5.psb);
  });
});
