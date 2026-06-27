// Internal-consistency tests for the Pasta field arithmetic (the in-TS ZKPP
// foundation). Cross-checks vs pasta_curves (encoding / from_uniform_bytes) need
// Rust test vectors and are added separately.
import { describe, it, expect } from 'vitest';
import { Fp, Fq, FP_MODULUS, FQ_MODULUS } from '../src/zkpp/field.js';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

// Reference vectors from sid-pake-core/tests/interop_vectors.rs (pasta_curves).
describe('Pasta field — Rust interop vectors (pasta_curves)', () => {
  it('Fp.toBytes(7) == pasta Base::from(7).to_repr (LE)', () => {
    expect(hex(Fp.toBytes(7n))).toBe('07' + '00'.repeat(31));
  });
  it('Fq.toBytes(7) == pasta Scalar::from(7).to_repr (LE)', () => {
    expect(hex(Fq.toBytes(7n))).toBe('07' + '00'.repeat(31));
  });
  it('Fq.fromUniformBytes([1;64]) == pasta Scalar::from_uniform_bytes', () => {
    const r = Fq.fromUniformBytes(new Uint8Array(64).fill(1));
    expect(hex(Fq.toBytes(r))).toBe(
      '1e1d1d1dca994821c5d6a028333f0d4396a0d3cebe9bed6dc4e9199dedab3e35',
    );
  });
});

const A = 0x123456789abcdef0fedcba9876543210123456789abcdef0fedcba98765432n;
const B = 0x0fedcba9876543210123456789abcdef0fedcba9876543210123456789abcdn;

for (const [name, F, P] of [
  ['Fp', Fp, FP_MODULUS],
  ['Fq', Fq, FQ_MODULUS],
] as const) {
  describe(`Pasta ${name} field`, () => {
    it('Fermat: a^(p-1) == 1 (modulus is prime)', () => {
      expect(F.pow(A % P, P - 1n)).toBe(1n);
      expect(F.pow(B % P, P - 1n)).toBe(1n);
    });

    it('additive inverse: a + (-a) == 0', () => {
      const a = F.mod(A);
      expect(F.add(a, F.neg(a))).toBe(0n);
    });

    it('multiplicative inverse: a * inv(a) == 1', () => {
      const a = F.mod(A);
      expect(F.mul(a, F.inv(a))).toBe(1n);
    });

    it('distributive: a*(b+c) == a*b + a*c', () => {
      const a = F.mod(A);
      const b = F.mod(B);
      const c = F.mod(A + B);
      expect(F.mul(a, F.add(b, c))).toBe(F.add(F.mul(a, b), F.mul(a, c)));
    });

    it('toBytes/fromBytes roundtrip (32-byte LE canonical)', () => {
      const a = F.mod(A);
      const bytes = F.toBytes(a);
      expect(bytes.length).toBe(32);
      expect(F.fromBytes(bytes)).toBe(a);
    });

    it('fromBytes rejects non-canonical (>= modulus)', () => {
      const tooBig = new Uint8Array(32).fill(0xff); // 2^256-1 > p
      expect(() => F.fromBytes(tooBig)).toThrow();
    });

    it('fromUniformBytes reduces into [0, p)', () => {
      const wide = new Uint8Array(64).fill(0xff);
      const r = F.fromUniformBytes(wide);
      expect(r).toBeLessThan(P);
      expect(r).toBeGreaterThanOrEqual(0n);
    });
  });
}
