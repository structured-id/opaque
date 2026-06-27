// TS ZKPP primitive suite benchmark at proof scale (k=11, n=2048).
// Quantifies the TS prover's per-operation cost (the full TS create_proof is not
// yet implemented; these are the building blocks it will be composed from).
import { bench, describe } from 'vitest';
import { Pallas, Vesta } from '../src/zkpp/curve.js';
import { poseidonHash2 } from '../src/zkpp/poseidon.js';
import { hashToCurveOutside } from '../src/zkpp/hash-to-curve.js';
import { bestFft, omegaForSize } from '../src/zkpp/fft.js';
import { ipaCommit, type IpaParams } from '../src/zkpp/ipa.js';
import { Transcript } from '../src/zkpp/transcript.js';

const N = 2048;
const LOGN = 11;
const omega = omegaForSize(LOGN);
const coeffs = Array.from({ length: N }, (_, i) => BigInt(i + 1));

// Setup: n=2048 Vesta bases + scalars for the commitment MSM.
const g: { x: bigint; y: bigint }[] = [];
for (let i = 0; i < N; i++)
  g.push(Vesta.scalarMul(BigInt(i + 1), Vesta.GENERATOR) as { x: bigint; y: bigint });
const params: IpaParams = { g, w: Vesta.GENERATOR };
const pw = new TextEncoder().encode('Str0ngP@ssword!');

describe('TS ZKPP suite (k=11, n=2048)', () => {
  bench('FFT n=2048 (NTT)', () => {
    bestFft([...coeffs], omega, LOGN);
  });
  bench('IPA commit n=2048 (MSM, pippenger)', () => {
    ipaCommit(params, coeffs, 7n);
  });
  bench('Poseidon hash2', () => {
    poseidonHash2(1n, 2n);
  });
  bench('HashToCurve (Poseidon + try-increment)', () => {
    hashToCurveOutside(pw);
  });
  bench('Pallas scalarMul', () => {
    Pallas.scalarMul(12345n, Pallas.GENERATOR);
  });
  bench('transcript squeeze', () => {
    const t = new Transcript();
    t.commonScalar(42n);
    t.squeezeChallenge();
  });
});
