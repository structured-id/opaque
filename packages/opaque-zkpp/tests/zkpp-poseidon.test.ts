// Poseidon (P128Pow5T3) interop vs sid_pake_core::poseidon. Vectors from
// interop_vectors.rs (dump_poseidon).
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/field.js';
import {
  poseidonHash2,
  poseidonHash1,
  computeHistoryCommitment,
  bytesToFieldElements,
} from '../src/poseidon.js';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));
const te = new TextEncoder();

describe('Poseidon P128Pow5T3 — Rust interop', () => {
  it('poseidonHash2(1, 2) matches Rust', () => {
    expect(fe(poseidonHash2(1n, 2n))).toBe(
      '4ce3bd9407dc758983c62390ce00463beb82796eb0d40a0398993cb4eca55535',
    );
  });

  it('poseidonHash1(7) matches Rust', () => {
    expect(fe(poseidonHash1(7n))).toBe(
      'c4443c01cdfc9df3d732b50c18ff55b688d1f30f264532836f2a180ca7636c0c',
    );
  });

  it('computeHistoryCommitment("Str0ngP@ssword!", [42;32]) matches Rust', () => {
    const salt = new Uint8Array(32).fill(42);
    expect(fe(computeHistoryCommitment(te.encode('Str0ngP@ssword!'), salt))).toBe(
      '7abaeb1895a7d75cbdfe533b838bdcf5280311b2a88a8dade37c8ba780256a29',
    );
  });

  it('bytesToFieldElements packs 31-byte LE chunks', () => {
    expect(bytesToFieldElements(new Uint8Array(11)).length).toBe(1); // "hello world" length
    expect(bytesToFieldElements(new Uint8Array(128)).length).toBe(5); // ceil(128/31)
  });
});
