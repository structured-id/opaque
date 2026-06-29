// Gadget D breach-bloom witness interop vs sid-pake-core gadget_d.
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/field.js';
import { breachHash, hashBits, bloomIndices } from '../src/circuit/gadget-d.js';
import gd from './fixtures/gadget-d.json';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

describe('gadget D breach-bloom witness — halo2 interop', () => {
  it('breach_hash + 255-bit decomp + k indices match gadget_d', () => {
    const pw = [...new TextEncoder().encode('Str0ngP@ss')];
    const hash = breachHash(pw, gd.padlen);
    expect(hex(Fp.toBytes(hash))).toBe(gd.hash);
    expect(hashBits(hash).join('')).toBe(gd.bits);
    expect(bloomIndices(hash, gd.k, gd.ib)).toEqual(gd.indices);
  });
});
