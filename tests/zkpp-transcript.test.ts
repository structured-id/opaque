// Transcript interop vs halo2 Blake2bWrite. Vector from interop_vectors.rs
// (dump_transcript): absorb 3·G (Vesta) + scalar 42, squeeze challenge.
import { describe, it, expect } from 'vitest';
import { Fp, Fq } from '../src/zkpp/field.js';
import { Vesta } from '../src/zkpp/curve.js';
import { Transcript } from '../src/zkpp/transcript.js';

const bytes = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

const TR_POINT = '5fce556feb6fee5a15560ddabae10224b026a5d0281af4c613955c39a8797837';
const TR_SCALAR = 42n;
const TR_CHALLENGE = '2628c63bda129328bfefc6dfd43011b190b5360263c864ef6ea3f842aae5291e';

describe('Blake2b transcript — halo2 interop', () => {
  it('absorb(3·G, 42) → squeeze challenge matches Rust', () => {
    const t = new Transcript();
    t.commonPoint(Vesta.fromBytes(bytes(TR_POINT)) as { x: bigint; y: bigint });
    t.commonScalar(TR_SCALAR);
    const ch = t.squeezeChallenge();
    expect(hex(Fp.toBytes(ch))).toBe(TR_CHALLENGE);
  });

  it('decoded TR_POINT is 3·G on Vesta', () => {
    const p = Vesta.fromBytes(bytes(TR_POINT)) as { x: bigint; y: bigint };
    expect(hex(Vesta.toBytes(Vesta.scalarMul(3n, Vesta.GENERATOR)))).toBe(hex(Vesta.toBytes(p)));
    expect(Fq.toBytes(p.x).length).toBe(32);
  });
});
