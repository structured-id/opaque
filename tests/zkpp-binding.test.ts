// Okamoto binding interop vs Rust sid_pake_core::binding.
// The decisive test: TS verifies a Rust-generated BindingProof — if it passes,
// the whole stack (Pasta field/curve, compressed encoding, SHA-512 transcript,
// from_uniform_bytes) is byte-identical to Rust.
import { describe, it, expect } from 'vitest';
import { verifyBinding, proveBinding, G2, type BindingProof } from '../src/zkpp/binding.js';
import { type Point, scalarMul, add, GENERATOR } from '../src/zkpp/curve.js';

const te = new TextEncoder();
function leHex(h: string): bigint {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
}
const pt = (x: string, y: string): Point => ({ x: leHex(x), y: leHex(y) });

// Vector from sid-pake-core/tests/interop_vectors.rs (print_binding_vector).
const COM = pt(
  'd10e70fdf461fb465db10c602adbd7b3fd9fdb0d492d1ecd4cbdffedecaa0a33',
  '859270e8a16c4427d826799a3451f708b9b4ad21ab7116dbee53aba4a2a27004',
);
const M = pt(
  '2188b0834b42cba66bbd9ca58b850e4c8ebcc2d60c3cf2637afeab622b32250f',
  'd1ad03be6b547705dc5b8517ed7634fdbea4b2ecdf4aba506bdb7bf85846ee0f',
);
const RUST_PROOF: BindingProof = {
  rCommit: pt(
    '7425e8c76493c1243cd2883c45f91c8c6880738268cf2dad8414d82cbe949327',
    '7860bd9536ae19c5f73b7ea7f2a93796782f7ccb3de6458cb3916239cc2d623f',
  ),
  z1: leHex('6b34c3ac60e36d3ad4ebd1835453dfc4211777bc1073d7ce11b4ac573d047712'),
  z2: leHex('87ead43831c9ecdcee1ff71c93b79ca8a55a4efde9ba28a777a76783d396990d'),
};

describe('Okamoto binding — Rust interop', () => {
  it('G2 constant matches pasta hash_to_curve vector', () => {
    expect(G2!.x).toBe(
      leHex('b5910af07299e793b6e77cd798043fc27c7fd87a1e52f7c7499eef204cd3fe24'),
    );
    expect(G2!.y).toBe(
      leHex('2bf91e17a829f947b667b3fa8f58ebd1553a4d16d9a36c96a91c2fdb4148b411'),
    );
  });

  it('TS verifies a Rust-generated BindingProof (full-stack byte-parity)', () => {
    expect(verifyBinding(te.encode('test-context'), COM, M, RUST_PROOF)).toBe(true);
  });

  it('rejects the Rust proof under a wrong context', () => {
    expect(verifyBinding(te.encode('wrong-context'), COM, M, RUST_PROOF)).toBe(false);
  });

  it('TS prove → TS verify roundtrip', () => {
    const ctx = te.encode('roundtrip');
    const com = scalarMul(5n, GENERATOR);
    const alpha = 7n;
    const beta = 11n;
    const m = add(scalarMul(alpha, com), scalarMul(beta, G2));
    const ks = [111n, 222n];
    let i = 0;
    const proof = proveBinding(ctx, com, m, alpha, beta, () => ks[i++]);
    expect(verifyBinding(ctx, com, m, proof)).toBe(true);
  });

  it('rejects a tampered proof (z1 + 1)', () => {
    const ctx = te.encode('roundtrip');
    const com = scalarMul(5n, GENERATOR);
    const m = add(scalarMul(7n, com), scalarMul(11n, G2));
    const ks = [111n, 222n];
    let i = 0;
    const proof = proveBinding(ctx, com, m, 7n, 11n, () => ks[i++]);
    proof.z1 = proof.z1 + 1n;
    expect(verifyBinding(ctx, com, m, proof)).toBe(false);
  });
});
