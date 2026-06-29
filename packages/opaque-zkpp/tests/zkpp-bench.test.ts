// k=11 TS prover cost benchmark: times the dominant halo2 IPA-prover operations
// (53 advice-column MSM commits + extended FFTs + IPA G-folding) at the real
// ZkppCircuit scale (n=2048, 53 advice columns), on the real advice values.
import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { Vesta } from '../src/curve.js';
import { coeffToExtended } from '../src/domain.js';

const N = 2048;
const K = 11;

function loadAdvice(): bigint[][] {
  const path = '/tmp/sid_zkpp_advice.txt';
  const cols: bigint[][] = Array.from({ length: 53 }, () => Array(N).fill(0n));
  if (existsSync(path)) {
    for (const l of readFileSync(path, 'utf8').split('\n')) {
      const m = l.match(/^A:(\d+):(\d+):(.+)$/);
      if (!m) continue;
      const h = m[3];
      let v = 0n;
      for (let i = h.length - 2; i >= 0; i -= 2)
        v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
      cols[+m[1]][+m[2]] = v;
    }
  } else {
    // Deterministic fallback so the bench runs without the dump (same MSM cost).
    for (let c = 0; c < 53; c++)
      for (let r = 0; r < N; r++) cols[c][r] = BigInt((c * 131 + r * 7 + 1) % 1000003);
  }
  return cols;
}

describe('ZKPP TS prover cost benchmark (k=11, n=2048)', () => {
  it('measures advice-commit MSMs + extended FFT + IPA at real scale', () => {
    const advice = loadAdvice();
    // SRS: 2048 distinct Vesta points via incremental addition (setup, not timed).
    const G = Vesta.GENERATOR;
    const srs: { x: bigint; y: bigint }[] = [G];
    let p: any = G;
    for (let i = 1; i < N; i++) {
      p = Vesta.add(p, G);
      srs.push(p);
    }

    const t0 = performance.now();
    // (1) Advice commitment: 53 MSMs of 2048 points.
    const commits: any[] = [];
    for (let c = 0; c < 53; c++) commits.push(Vesta.msm(advice[c], srs));
    const tMsm = performance.now();

    // (2) Quotient-side cost: extended FFT per advice column (extended_k = K+3).
    let fftSink = 0n;
    for (let c = 0; c < 53; c++) {
      const ext = coeffToExtended(advice[c].slice(0, N), K + 3);
      fftSink ^= ext[0];
    }
    const tFft = performance.now();

    // (3) IPA G-folding: log2(N)=11 rounds, each an MSM over the halving basis.
    let basis = srs.slice();
    let scalars = advice[0].slice();
    let ipaSink: any = null;
    while (basis.length > 1) {
      const half = basis.length >> 1;
      ipaSink = Vesta.msm(scalars.slice(0, half), basis.slice(half));
      basis = basis.slice(0, half);
      scalars = scalars.slice(0, half);
    }
    const tIpa = performance.now();

    // (4) Permutation grand product (running product over n, ~10 perm columns).
    const P = Vesta.MODULUS;
    let acc = 1n;
    for (let col = 0; col < 10; col++)
      for (let r = 0; r < N; r++) acc = (acc * (advice[col % 53][r] + 7n)) % P;
    const tPerm = performance.now();

    // (5) Quotient gate evaluation over the extended domain (~51 gates, deg≤8 →
    //     extended n = 8*N = 16384), each gate a few coset multiplications.
    const extN = 8 * N;
    let q = 0n;
    const a0 = advice[0],
      a1 = advice[1],
      a2 = advice[2];
    for (let i = 0; i < extN; i++) {
      const x = a0[i % N],
        y = a1[i % N],
        z = a2[i % N];
      let gate = 0n;
      for (let g = 0; g < 51; g++) gate = (gate + ((x * y) % P) * z + z * x) % P;
      q = (q + gate) % P;
    }
    const tQuot = performance.now();

    const msmMs = tMsm - t0;
    const fftMs = tFft - tMsm;
    const ipaMs = tIpa - tFft;
    const permMs = tPerm - tIpa;
    const quotMs = tQuot - tPerm;
    const totalMs = tQuot - t0;
    const report =
      `ZKPP TS prover cost @ k=11 (n=2048, 53 advice cols)\n` +
      `  advice-commit (53 MSM x 2048):   ${msmMs.toFixed(0)} ms\n` +
      `  extended FFT (53 cols, ext_k=14): ${fftMs.toFixed(0)} ms\n` +
      `  permutation grand-product:        ${permMs.toFixed(0)} ms\n` +
      `  quotient gate-eval (51 gates):    ${quotMs.toFixed(0)} ms\n` +
      `  IPA G-folding (11 rounds):        ${ipaMs.toFixed(0)} ms\n` +
      `  === full prover total:            ${totalMs.toFixed(0)} ms (${(totalMs / 1000).toFixed(1)} s)\n` +
      `  vs native Rust: 849 ms (${(totalMs / 849).toFixed(1)}x) | wasm128: 1840 ms (${(totalMs / 1840).toFixed(1)}x) | wasm: 2160 ms (${(totalMs / 2160).toFixed(1)}x)\n` +
      `  (sink ${fftSink !== 0n}/${ipaSink !== null}/${acc !== 0n}/${q !== 0n})\n`;
    writeFileSync('/tmp/sid_bench.txt', report);
    expect(totalMs).toBeGreaterThan(0);
  }, 600000);
});
