// TS ZKPP primitive benchmarks (BigInt affine) — to quantify TS-vs-native/WASM
// slowdown. Pair with the Rust criterion bench (sid-pake-core/benches/zkpp.rs).
import { bench, describe } from 'vitest';
import { scalarMul, GENERATOR, add, type Point } from '../src/zkpp/curve.js';
import { verifyBinding, type BindingProof } from '../src/zkpp/binding.js';

const te = new TextEncoder();
const leHex = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};
const pt = (x: string, y: string): Point => ({ x: leHex(x), y: leHex(y) });

const K = leHex('6b34c3ac60e36d3ad4ebd1835453dfc4211777bc1073d7ce11b4ac573d047712');
const COM = pt(
  'd10e70fdf461fb465db10c602adbd7b3fd9fdb0d492d1ecd4cbdffedecaa0a33',
  '859270e8a16c4427d826799a3451f708b9b4ad21ab7116dbee53aba4a2a27004',
);
const M = pt(
  '2188b0834b42cba66bbd9ca58b850e4c8ebcc2d60c3cf2637afeab622b32250f',
  'd1ad03be6b547705dc5b8517ed7634fdbea4b2ecdf4aba506bdb7bf85846ee0f',
);
const PROOF: BindingProof = {
  rCommit: pt(
    '7425e8c76493c1243cd2883c45f91c8c6880738268cf2dad8414d82cbe949327',
    '7860bd9536ae19c5f73b7ea7f2a93796782f7ccb3de6458cb3916239cc2d623f',
  ),
  z1: leHex('6b34c3ac60e36d3ad4ebd1835453dfc4211777bc1073d7ce11b4ac573d047712'),
  z2: leHex('87ead43831c9ecdcee1ff71c93b79ca8a55a4efde9ba28a777a76783d396990d'),
};
const ctx = te.encode('test-context');

describe('zkpp TS primitives (BigInt, affine)', () => {
  bench('Pallas scalarMul (255-bit)', () => {
    scalarMul(K, GENERATOR);
  });
  bench('Pallas point add', () => {
    add(GENERATOR, COM);
  });
  bench('Okamoto binding verify (3 scalarMuls + SHA-512)', () => {
    verifyBinding(ctx, COM, M, PROOF);
  });
});
