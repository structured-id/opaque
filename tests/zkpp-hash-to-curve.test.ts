// Native HashToCurve (gadget C) interop vs Rust gadget_c::hash_to_curve_outside.
// Vector from interop_vectors.rs (dump_poseidon → HP_*).
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/zkpp/field.js';
import { hashToCurveOutside } from '../src/zkpp/hash-to-curve.js';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));
const te = new TextEncoder();

const HP_X = '0e06d86167c3e8564a6aed401e3a23650bcd5c43df79350eb279ed55c29dd23d';
const HP_Y = 'ef769bb173a4fc79dbf0f84c776332b0b8190f1fc41c685eb749be34f6caa13e';
const HP_U = '0e06d86167c3e8564a6aed401e3a23650bcd5c43df79350eb279ed55c29dd23d';

describe('Native HashToCurve (gadget C) — Rust interop', () => {
  const r = hashToCurveOutside(te.encode('Str0ngP@ssword!'));

  it('u = Poseidon(password) matches Rust', () => {
    expect(fe(r.u)).toBe(HP_U);
  });

  it('offset is 0 (u itself yields a curve point)', () => {
    expect(r.offset).toBe(0n);
  });

  it('H_p.x matches Rust', () => {
    expect(fe(r.point.x)).toBe(HP_X);
  });

  it('H_p.y matches Rust sqrt convention', () => {
    expect(fe(r.point.y)).toBe(HP_Y);
  });

  it('H_p is on the curve (y² = x³ + 5)', () => {
    expect(Fp.square(r.point.y)).toBe(Fp.add(Fp.mul(Fp.square(r.point.x), r.point.x), 5n));
  });
});
