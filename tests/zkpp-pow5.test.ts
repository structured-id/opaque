// Pow5 Poseidon-chip witness layout: checkpoint states reproduce the hash output.
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/zkpp/field.js';
import { permuteWithCells, poseidonHash2 } from '../src/zkpp/poseidon.js';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));

describe('Pow5 Poseidon-chip witness layout', () => {
  it('checkpoint states reproduce poseidonHash2 with correct Pow5 row structure', () => {
    const a = 2n;
    const b = 3n;
    const cells = permuteWithCells([a, b, 2n << 64n]);
    expect(cells.states.length).toBe(37); // load + 4 full + 28 partial-pairs + 4 full
    expect(cells.partialSbox.length).toBe(28);
    expect(cells.states.every((s) => s.length === 3)).toBe(true);
    // Final state lane 0 = the ConstantLength<2> hash output.
    expect(fe(cells.states[36][0])).toBe(fe(poseidonHash2(a, b)));
  });
});
