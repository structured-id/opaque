// Real ZkppCircuit create_proof — stage by stage vs the Rust proof bytes.
// Stage 1: advice commitment (53 MSMs on the real SRS + CounterRng blinds).
// Reads /tmp dumps (measurement) — skips in CI.
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { Vesta } from '../src/curve.js';
import { commitAdvice, CounterRng } from '../src/prover.js';
import { leHex } from '../src/gate-eval.js';
import { Fp as FpReal } from '../src/field.js';
import { writeFileSync } from 'fs';

const N = 2048;
const fromHexBytes = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));

describe('real ZkppCircuit create_proof — stage 1 advice commitment', () => {
  it('53 advice commitments on real SRS match the Rust proof prefix', () => {
    if (!existsSync('/tmp/sid_zkpp_srs.txt') || !existsSync('/tmp/sid_zkpp_proof.txt')) {
      console.log('SKIP: no dumps');
      return;
    }
    // Real SRS.
    const gLagrange: { x: bigint; y: bigint }[] = new Array(N);
    let w: { x: bigint; y: bigint } | null = null;
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gLagrange[+m[1]] = Vesta.fromBytes(fromHexBytes(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHexBytes(m[1])) as { x: bigint; y: bigint };
    }
    // Dumped advice (full columns incl blinding; commitAdvice regenerates blinding
    // identically from CounterRng, so witness rows are what matter).
    const advice: bigint[][] = Array.from({ length: 53 }, () => Array(N).fill(0n));
    for (const l of readFileSync('/tmp/sid_zkpp_advice.txt', 'utf8').split('\n')) {
      const m = l.match(/^A:(\d+):(\d+):(.+)$/);
      if (m) advice[+m[1]][+m[2]] = leHex(m[3]);
    }
    const res = commitAdvice(
      { gLagrange, w: w!, n: N, blindingFactors: 5 },
      advice,
      new CounterRng(),
    );
    // Proof prefix = 53 advice commitments (32 compressed bytes each).
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const hx = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    let matched = 0;
    for (let c = 0; c < 53; c++) {
      const mine = hx(Vesta.toBytes(res.commitments[c]));
      const ref = proofHex.slice(c * 64, c * 64 + 64);
      if (mine === ref) matched++;
      else if (c < 2) console.log(`col${c}: mine=${mine.slice(0, 16)} ref=${ref.slice(0, 16)}`);
    }
    console.log(`ADVICE-COMMIT: ${matched}/53 commitments match Rust proof`);
    expect(matched).toBe(53);
  }, 120000);
});

import { Transcript } from '../src/transcript.js';

describe('real ZkppCircuit create_proof — stage 2 theta challenge', () => {
  it('transcript (vk_repr + instance commit + advice commits) squeezes Rust theta', () => {
    if (!existsSync('/tmp/sid_zkpp_srs.txt')) {
      console.log('SKIP: no dumps');
      return;
    }
    const fe = (v: bigint) =>
      [...FpReal.toBytes(v)].map((x: number) => x.toString(16).padStart(2, '0')).join('');
    // Real SRS.
    const gLagrange: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gLagrange[+m[1]] = Vesta.fromBytes(fromHexBytes(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHexBytes(m[1])) as { x: bigint; y: bigint };
    }
    const advice: bigint[][] = Array.from({ length: 53 }, () => Array(N).fill(0n));
    for (const l of readFileSync('/tmp/sid_zkpp_advice.txt', 'utf8').split('\n')) {
      const m = l.match(/^A:(\d+):(\d+):(.+)$/);
      if (m) advice[+m[1]][+m[2]] = leHex(m[3]);
    }
    const adv = commitAdvice({ gLagrange, w, n: N, blindingFactors: 5 }, advice, new CounterRng());
    // vk_repr.
    const vkRepr = leHex(
      readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').match(/PK_VK_REPR=(\w+)/)![1],
    );
    // Instance commit: commit_lagrange(instance, Blind(1)).
    const inst = Array(N).fill(0n);
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) inst[+m[1]] = leHex(m[2]);
    }
    const instCommit = Vesta.add(Vesta.msm(inst, gLagrange), Vesta.scalarMul(1n, w));
    // Transcript: vk_repr → instance commit → advice commits → squeeze theta.
    const t = new Transcript();
    t.commonScalar(vkRepr);
    t.commonPoint(instCommit as NonNullable<typeof instCommit>);
    for (let c = 0; c < 53; c++) t.commonPoint(adv.commitments[c] as any);
    const theta = t.squeezeChallenge();
    writeFileSync(
      '/tmp/theta_mine.txt',
      `mine=${fe(theta)}\ninstCommit=${[...Vesta.toBytes(instCommit)].map((x) => x.toString(16).padStart(2, '0')).join('')}\n`,
    );
    expect(fe(theta)).toBe('c65ecb9f6053f97cba1c9ebbe68c999ef0ef08d44673956d2f10cd8902739321');
  }, 120000);
});

import { evalAst, type Ast, type EvalCtx } from '../src/gate-eval.js';

describe('real ZkppCircuit create_proof — stage 3a lookup compression', () => {
  it('theta-compressed input/table for all 6 lookups match Rust LK_CIN/LK_CTAB', () => {
    if (!existsSync('/tmp/sid_lk.txt') || !existsSync('/tmp/sid_zkpp_cs.txt')) {
      console.log('SKIP: no dumps');
      return;
    }
    const theta = leHex('c65ecb9f6053f97cba1c9ebbe68c999ef0ef08d44673956d2f10cd8902739321');
    // Load advice/fixed/instance.
    const advice: bigint[][] = Array.from({ length: 53 }, () => Array(N).fill(0n));
    for (const l of readFileSync('/tmp/sid_zkpp_advice.txt', 'utf8').split('\n')) {
      const m = l.match(/^A:(\d+):(\d+):(.+)$/);
      if (m) advice[+m[1]][+m[2]] = leHex(m[3]);
    }
    const fixed: bigint[][] = Array.from({ length: 55 }, () => Array(N).fill(0n));
    for (const l of readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').split('\n')) {
      const m = l.match(/^F:(\d+):(\d+):(.+)$/);
      if (m) fixed[+m[1]][+m[2]] = leHex(m[3]);
    }
    const instance = [Array(N).fill(0n)];
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) instance[0][+m[1]] = leHex(m[2]);
    }
    const ctx: EvalCtx = { advice, fixed, instance, n: N };
    // Parse lookup input/table expressions per lookup.
    const lkin: Ast[][] = [];
    const lktab: Ast[][] = [];
    for (const l of readFileSync('/tmp/sid_zkpp_cs.txt', 'utf8').split('\n')) {
      let m = l.match(/^LKIN:(\d+):(\d+):(.+)$/);
      if (m) (lkin[+m[1]] ??= [])[+m[2]] = JSON.parse(m[3]) as Ast;
      m = l.match(/^LKTAB:(\d+):(\d+):(.+)$/);
      if (m) (lktab[+m[1]] ??= [])[+m[2]] = JSON.parse(m[3]) as Ast;
    }
    // Rust dumps: DUMP_LK_CIN=<2048×32B hex>, one per lookup in order.
    const lkLines = readFileSync('/tmp/sid_lk.txt', 'utf8').split('\n');
    const cins = lkLines.filter((x) => x.startsWith('DUMP_LK_CIN=')).map((x) => x.slice(12));
    const ctabs = lkLines.filter((x) => x.startsWith('DUMP_LK_CTAB=')).map((x) => x.slice(13));
    const compress = (exprs: Ast[], row: number): bigint => {
      let acc = 0n;
      for (const e of exprs) acc = FpReal.add(FpReal.mul(acc, theta), evalAst(e, row, ctx));
      return acc;
    };
    const fe = (v: bigint) =>
      [...FpReal.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    let lookupsOk = 0;
    for (let l = 0; l < 6; l++) {
      let cinOk = true;
      let ctabOk = true;
      for (let r = 0; r < N; r++) {
        if (fe(compress(lkin[l], r)) !== cins[l].slice(r * 64, r * 64 + 64)) cinOk = false;
        if (fe(compress(lktab[l], r)) !== ctabs[l].slice(r * 64, r * 64 + 64)) ctabOk = false;
      }
      if (cinOk && ctabOk) lookupsOk++;
    }
    console.log(`LOOKUP-COMPRESS: ${lookupsOk}/6 lookups input+table match`);
    expect(lookupsOk).toBe(6);
  }, 120000);
});

import { permuteExpressionPair } from '../src/prover.js';

describe('real ZkppCircuit create_proof — stage 3b lookup permute + commit', () => {
  it('permuted A/S + 12 commitments match Rust (proof bytes + LK_AP/SP)', () => {
    if (!existsSync('/tmp/sid_lk2.txt')) {
      console.log('SKIP: no dumps');
      return;
    }
    const fe = (v: bigint) =>
      [...FpReal.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    const theta = leHex('c65ecb9f6053f97cba1c9ebbe68c999ef0ef08d44673956d2f10cd8902739321');
    // SRS.
    const gLagrange: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gLagrange[+m[1]] = Vesta.fromBytes(fromHexBytes(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHexBytes(m[1])) as { x: bigint; y: bigint };
    }
    // advice/fixed/instance.
    const advice: bigint[][] = Array.from({ length: 53 }, () => Array(N).fill(0n));
    for (const l of readFileSync('/tmp/sid_zkpp_advice.txt', 'utf8').split('\n')) {
      const m = l.match(/^A:(\d+):(\d+):(.+)$/);
      if (m) advice[+m[1]][+m[2]] = leHex(m[3]);
    }
    const fixed: bigint[][] = Array.from({ length: 55 }, () => Array(N).fill(0n));
    for (const l of readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').split('\n')) {
      const m = l.match(/^F:(\d+):(\d+):(.+)$/);
      if (m) fixed[+m[1]][+m[2]] = leHex(m[3]);
    }
    const instance = [Array(N).fill(0n)];
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) instance[0][+m[1]] = leHex(m[2]);
    }
    const ctx: EvalCtx = { advice, fixed, instance, n: N };
    const lkin: Ast[][] = [];
    const lktab: Ast[][] = [];
    for (const l of readFileSync('/tmp/sid_zkpp_cs.txt', 'utf8').split('\n')) {
      let m = l.match(/^LKIN:(\d+):(\d+):(.+)$/);
      if (m) (lkin[+m[1]] ??= [])[+m[2]] = JSON.parse(m[3]) as Ast;
      m = l.match(/^LKTAB:(\d+):(\d+):(.+)$/);
      if (m) (lktab[+m[1]] ??= [])[+m[2]] = JSON.parse(m[3]) as Ast;
    }
    const compress = (exprs: Ast[]): bigint[] =>
      Array.from({ length: N }, (_, r) => {
        let acc = 0n;
        for (const e of exprs) acc = FpReal.add(FpReal.mul(acc, theta), evalAst(e, r, ctx));
        return acc;
      });
    // Thread the RNG: advice (53×6 blinding + 53 blinds), then per-lookup.
    const rng = new CounterRng();
    commitAdvice({ gLagrange, w, n: N, blindingFactors: 5 }, advice, rng);
    const lk2 = readFileSync('/tmp/sid_lk2.txt', 'utf8').split('\n');
    const aps = lk2.filter((x) => x.startsWith('DUMP_LK_AP=')).map((x) => x.slice(11));
    const sps = lk2.filter((x) => x.startsWith('DUMP_LK_SP=')).map((x) => x.slice(11));
    const apc = lk2.filter((x) => x.startsWith('DUMP_LK_AP_COMMIT=')).map((x) => x.slice(18));
    const spc = lk2.filter((x) => x.startsWith('DUMP_LK_SP_COMMIT=')).map((x) => x.slice(18));
    const hx = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    const commitL = (vals: bigint[], blind: bigint) =>
      hx(Vesta.toBytes(Vesta.add(Vesta.msm(vals, gLagrange), Vesta.scalarMul(blind, w))));
    let apOk = 0,
      spOk = 0,
      apcOk = 0,
      spcOk = 0;
    for (let l = 0; l < 6; l++) {
      const ci = compress(lkin[l]);
      const ct = compress(lktab[l]);
      const { pInput, pTable } = permuteExpressionPair(ci, ct, N - 6, 5, rng);
      const blindA = rng.nextScalar();
      const blindS = rng.nextScalar();
      if (pInput.map(fe).join('') === aps[l]) apOk++;
      if (pTable.map(fe).join('') === sps[l]) spOk++;
      if (commitL(pInput, blindA) === apc[l]) apcOk++;
      if (commitL(pTable, blindS) === spc[l]) spcOk++;
    }
    console.log(
      `LOOKUP-PERMUTE: AP=${apOk}/6 SP=${spOk}/6 AP_COMMIT=${apcOk}/6 SP_COMMIT=${spcOk}/6`,
    );
    expect([apOk, spOk, apcOk, spcOk]).toEqual([6, 6, 6, 6]);
  }, 120000);
});

describe('real ZkppCircuit create_proof — stage 4 beta/gamma challenges', () => {
  it('transcript through lookup commits squeezes Rust beta + gamma', () => {
    if (!existsSync('/tmp/sid_zkpp_proof.txt') || !existsSync('/tmp/sid_zkpp_srs.txt')) {
      console.log('SKIP: no dumps');
      return;
    }
    const fe = (v: bigint) =>
      [...FpReal.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    // SRS (for instance commit).
    const gLagrange: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gLagrange[+m[1]] = Vesta.fromBytes(fromHexBytes(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHexBytes(m[1])) as { x: bigint; y: bigint };
    }
    const vkRepr = leHex(
      readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').match(/PK_VK_REPR=(\w+)/)![1],
    );
    const inst = Array(N).fill(0n);
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) inst[+m[1]] = leHex(m[2]);
    }
    const instCommit = Vesta.add(Vesta.msm(inst, gLagrange), Vesta.scalarMul(1n, w));
    // Proof points: 53 advice + 12 lookup permuted (32 compressed bytes each).
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const point = (i: number) => Vesta.fromBytes(fromHexBytes(proofHex.slice(i * 64, i * 64 + 64)));
    const t = new Transcript();
    t.commonScalar(vkRepr);
    t.commonPoint(instCommit as any);
    for (let i = 0; i < 53; i++) t.commonPoint(point(i) as any);
    t.squeezeChallenge(); // theta
    for (let i = 53; i < 65; i++) t.commonPoint(point(i) as any); // 12 lookup commits
    const beta = t.squeezeChallenge();
    const gamma = t.squeezeChallenge();
    console.log(`BETA/GAMMA: beta=${fe(beta).slice(0, 12)} gamma=${fe(gamma).slice(0, 12)}`);
    expect(fe(beta)).toBe('86e847078d289eabd9a203471b4964c924080266dda9710142fbaa8f0c0c2837');
    expect(fe(gamma)).toBe('cc5a8802603ccdca3f9dd351ec911c1f03d181e5ebcfc58635a9133dd4d8bf13');
  }, 120000);
});

import { permutationZChunk } from '../src/prover.js';
import { omegaForSize } from '../src/fft.js';

describe('real ZkppCircuit create_proof — stage 5a permutation grand-product Z', () => {
  it('8 chunk Z (56 cols, chained) match Rust DUMP_PERM_Z', () => {
    if (!existsSync('/tmp/sid_perm_z.txt')) {
      console.log('SKIP: no dumps');
      return;
    }
    const fe = (v: bigint) =>
      [...FpReal.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    const K = 11;
    const beta = leHex('86e847078d289eabd9a203471b4964c924080266dda9710142fbaa8f0c0c2837');
    const gamma = leHex('cc5a8802603ccdca3f9dd351ec911c1f03d181e5ebcfc58635a9133dd4d8bf13');
    const delta = leHex('a29b7bdd20cd6c6a3656ee3ef1f3e4f59d04a512715b45bd6cab06000f7d750a');
    // advice/fixed/instance.
    const advice: bigint[][] = Array.from({ length: 53 }, () => Array(N).fill(0n));
    for (const l of readFileSync('/tmp/sid_zkpp_advice.txt', 'utf8').split('\n')) {
      const m = l.match(/^A:(\d+):(\d+):(.+)$/);
      if (m) advice[+m[1]][+m[2]] = leHex(m[3]);
    }
    const fixed: bigint[][] = Array.from({ length: 55 }, () => Array(N).fill(0n));
    const sigmas: bigint[][] = Array.from({ length: 56 }, () => Array(N).fill(0n));
    for (const l of readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').split('\n')) {
      let m = l.match(/^F:(\d+):(\d+):(.+)$/);
      if (m) fixed[+m[1]][+m[2]] = leHex(m[3]);
      m = l.match(/^S:(\d+):(\d+):(.+)$/);
      if (m) sigmas[+m[1]][+m[2]] = leHex(m[3]);
    }
    const instance = [Array(N).fill(0n)];
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) instance[0][+m[1]] = leHex(m[2]);
    }
    // PERM column mapping.
    const permCols: bigint[][] = [];
    for (const l of readFileSync('/tmp/sid_zkpp_cs.txt', 'utf8').split('\n')) {
      const m = l.match(/^PERM:(\d+):(\d+):(\w+)/);
      if (m) {
        const ci = +m[2],
          ty = m[3];
        permCols[+m[1]] = ty === 'Advice' ? advice[ci] : ty === 'Fixed' ? fixed[ci] : instance[ci];
      }
    }
    const zdump = readFileSync('/tmp/sid_perm_z.txt', 'utf8')
      .split('\n')
      .filter((x) => x.startsWith('DUMP_PERM_Z='))
      .map((x) => x.slice(12));
    // delta powers δ^0..δ^55.
    const dpow = [1n];
    for (let i = 1; i < 56; i++) dpow.push(FpReal.mul(dpow[i - 1], delta));
    const CHUNK = 7;
    let lastZ = 1n;
    let chunksOk = 0;
    for (let c = 0; c < 8; c++) {
      const cols = permCols.slice(c * CHUNK, c * CHUNK + CHUNK);
      const sigs = sigmas.slice(c * CHUNK, c * CHUNK + CHUNK);
      const dps = dpow.slice(c * CHUNK, c * CHUNK + CHUNK);
      const z = permutationZChunk(cols, sigs, dps, beta, gamma, K, lastZ);
      if (z.map(fe).join('') === zdump[c]) chunksOk++;
      else if (c < 2)
        console.log(
          `chunk${c} mismatch (z[1] mine=${fe(z[1]).slice(0, 12)} rust=${zdump[c].slice(64, 76)})`,
        );
      lastZ = z[N - 6]; // carry z at last usable row (n - (bf+1))
    }
    console.log(`PERM-Z: ${chunksOk}/8 chunks match`);
    expect(chunksOk).toBe(8);
  }, 120000);
});

describe('real ZkppCircuit create_proof — stage 5b permutation Z commitments', () => {
  it('8 permutation Z commitments match Rust proof[65..73]', () => {
    if (!existsSync('/tmp/sid_perm_z.txt') || !existsSync('/tmp/sid_zkpp_proof.txt')) {
      console.log('SKIP: no dumps');
      return;
    }
    const gLagrange: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gLagrange[+m[1]] = Vesta.fromBytes(fromHexBytes(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHexBytes(m[1])) as { x: bigint; y: bigint };
    }
    // DUMP_PERM_Z = grand product (pre-blinding), 8 chunks × 2048.
    const zdump = readFileSync('/tmp/sid_perm_z.txt', 'utf8')
      .split('\n')
      .filter((x) => x.startsWith('DUMP_PERM_Z='))
      .map((x) => x.slice(12));
    const parseCol = (h: string) =>
      Array.from({ length: N }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    // Thread RNG: advice (53×6 + 53) + 6 lookups (6×14) consumed before perm Z.
    const rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14; i++) rng.nextScalar();
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const hx = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    let ok = 0;
    for (let c = 0; c < 8; c++) {
      const z = parseCol(zdump[c]);
      for (let r = N - 5; r < N; r++) z[r] = rng.nextScalar(); // 5 blinding rows
      const blind = rng.nextScalar();
      const commit = hx(
        Vesta.toBytes(Vesta.add(Vesta.msm(z, gLagrange), Vesta.scalarMul(blind, w))),
      );
      if (commit === proofHex.slice((65 + c) * 64, (65 + c) * 64 + 64)) ok++;
    }
    console.log(`PERM-Z-COMMIT: ${ok}/8 match proof`);
    expect(ok).toBe(8);
  }, 120000);
});

describe('real ZkppCircuit create_proof — stage 5c lookup product Z commitments', () => {
  it('6 lookup product Z commitments match Rust proof[73..79]', () => {
    if (
      !existsSync('/tmp/sid_lk.txt') ||
      !existsSync('/tmp/sid_lk2.txt') ||
      !existsSync('/tmp/sid_zkpp_proof.txt')
    ) {
      console.log('SKIP: no dumps');
      return;
    }
    const gLagrange: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gLagrange[+m[1]] = Vesta.fromBytes(fromHexBytes(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHexBytes(m[1])) as { x: bigint; y: bigint };
    }
    const beta = leHex('86e847078d289eabd9a203471b4964c924080266dda9710142fbaa8f0c0c2837');
    const gamma = leHex('cc5a8802603ccdca3f9dd351ec911c1f03d181e5ebcfc58635a9133dd4d8bf13');
    const parseCol = (h: string) =>
      Array.from({ length: N }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const lk = readFileSync('/tmp/sid_lk.txt', 'utf8').split('\n');
    const lk2 = readFileSync('/tmp/sid_lk2.txt', 'utf8').split('\n');
    const cins = lk.filter((x) => x.startsWith('DUMP_LK_CIN=')).map((x) => parseCol(x.slice(12)));
    const ctabs = lk.filter((x) => x.startsWith('DUMP_LK_CTAB=')).map((x) => parseCol(x.slice(13)));
    const aps = lk2.filter((x) => x.startsWith('DUMP_LK_AP=')).map((x) => parseCol(x.slice(11)));
    const sps = lk2.filter((x) => x.startsWith('DUMP_LK_SP=')).map((x) => parseCol(x.slice(11)));
    const rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14 + 8 * 6; i++) rng.nextScalar(); // advice + lookups permuted + 8 perm Z
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const hx = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    let ok = 0;
    for (let l = 0; l < 6; l++) {
      // lookup_product[i] = (cin+β)(ctab+γ) / ((A'+β)(S'+γ))
      const lp = Array.from({ length: N }, (_, i) =>
        FpReal.mul(
          FpReal.mul(FpReal.add(cins[l][i], beta), FpReal.add(ctabs[l][i], gamma)),
          FpReal.inv(FpReal.mul(FpReal.add(aps[l][i], beta), FpReal.add(sps[l][i], gamma))),
        ),
      );
      const z = new Array(N).fill(0n);
      z[0] = 1n;
      for (let i = 1; i < N - 5; i++) z[i] = FpReal.mul(z[i - 1], lp[i - 1]); // grand product take(n-bf)
      for (let i = N - 5; i < N; i++) z[i] = rng.nextScalar(); // 5 blinding rows
      const blind = rng.nextScalar();
      const commit = hx(
        Vesta.toBytes(Vesta.add(Vesta.msm(z, gLagrange), Vesta.scalarMul(blind, w))),
      );
      if (commit === proofHex.slice((73 + l) * 64, (73 + l) * 64 + 64)) ok++;
    }
    console.log(`LOOKUP-Z-COMMIT: ${ok}/6 match proof`);
    expect(ok).toBe(6);
  }, 120000);
});

describe('real ZkppCircuit create_proof — stage 6a y challenge', () => {
  it('transcript through vanishing-random commit squeezes Rust y', () => {
    if (!existsSync('/tmp/sid_zkpp_proof.txt')) {
      console.log('SKIP');
      return;
    }
    const fe = (v: bigint) =>
      [...FpReal.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    const gLagrange: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gLagrange[+m[1]] = Vesta.fromBytes(fromHexBytes(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHexBytes(m[1])) as { x: bigint; y: bigint };
    }
    const vkRepr = leHex(
      readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').match(/PK_VK_REPR=(\w+)/)![1],
    );
    const inst = Array(N).fill(0n);
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) inst[+m[1]] = leHex(m[2]);
    }
    const instCommit = Vesta.add(Vesta.msm(inst, gLagrange), Vesta.scalarMul(1n, w));
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const point = (i: number) => Vesta.fromBytes(fromHexBytes(proofHex.slice(i * 64, i * 64 + 64)));
    const t = new Transcript();
    t.commonScalar(vkRepr);
    t.commonPoint(instCommit as any);
    for (let i = 0; i < 53; i++) t.commonPoint(point(i) as any); // advice
    t.squeezeChallenge(); // theta
    for (let i = 53; i < 65; i++) t.commonPoint(point(i) as any); // 12 lookup permuted
    t.squeezeChallenge(); // beta
    t.squeezeChallenge(); // gamma
    for (let i = 65; i < 73; i++) t.commonPoint(point(i) as any); // 8 perm Z
    for (let i = 73; i < 79; i++) t.commonPoint(point(i) as any); // 6 lookup Z
    t.commonPoint(point(79) as any); // vanishing random commit
    const y = t.squeezeChallenge();
    console.log(`Y: mine=${fe(y).slice(0, 12)} rust=600dc9505e3c`);
    expect(fe(y)).toBe('600dc9505e3c6df6b518db6afa47e0ae0aa8157ec0996502e5e86a1edc93920b');
  }, 120000);
});

describe('real ZkppCircuit create_proof — stage 7a x challenge', () => {
  it('transcript through 8 h-commits squeezes Rust x', () => {
    if (!existsSync('/tmp/sid_zkpp_proof.txt')) {
      console.log('SKIP');
      return;
    }
    const fe = (v: bigint) =>
      [...FpReal.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    const gLagrange: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gLagrange[+m[1]] = Vesta.fromBytes(fromHexBytes(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHexBytes(m[1])) as { x: bigint; y: bigint };
    }
    const vkRepr = leHex(
      readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').match(/PK_VK_REPR=(\w+)/)![1],
    );
    const inst = Array(N).fill(0n);
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) inst[+m[1]] = leHex(m[2]);
    }
    const instCommit = Vesta.add(Vesta.msm(inst, gLagrange), Vesta.scalarMul(1n, w));
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const point = (i: number) => Vesta.fromBytes(fromHexBytes(proofHex.slice(i * 64, i * 64 + 64)));
    const t = new Transcript();
    t.commonScalar(vkRepr);
    t.commonPoint(instCommit as any);
    for (let i = 0; i < 53; i++) t.commonPoint(point(i) as any);
    t.squeezeChallenge(); // theta
    for (let i = 53; i < 65; i++) t.commonPoint(point(i) as any);
    t.squeezeChallenge();
    t.squeezeChallenge(); // beta, gamma
    for (let i = 65; i < 79; i++) t.commonPoint(point(i) as any); // 8 permZ + 6 lookupZ
    t.commonPoint(point(79) as any); // vanishing random
    t.squeezeChallenge(); // y
    for (let i = 80; i < 88; i++) t.commonPoint(point(i) as any); // 8 h commits
    const x = t.squeezeChallenge();
    console.log(`X: mine=${fe(x).slice(0, 12)} rust=8176ef85`);
    expect(fe(x)).toBe('8176ef85595455da940b6aa36cdd5dc7807a724b58af8ef0148af74bdb7f8517');
  }, 120000);
});

import { evalPolynomial } from '../src/prover.js';
import { lagrangeToCoeff } from '../src/domain.js';

describe('real ZkppCircuit create_proof — stage 7b instance/advice/fixed evals', () => {
  it('155 evals at x match Rust proof eval section', () => {
    if (!existsSync('/tmp/sid_zkpp_proof.txt')) {
      console.log('SKIP');
      return;
    }
    const K = 11;
    const x = leHex('8176ef85595455da940b6aa36cdd5dc7807a724b58af8ef0148af74bdb7f8517');
    const omega = omegaForSize(K);
    const fe = (v: bigint) =>
      [...FpReal.toBytes(v)].map((b) => b.toString(16).padStart(2, '0')).join('');
    const loadL = (path: string, tag: string, nc: number) => {
      const cols = Array.from({ length: nc }, () => Array(N).fill(0n));
      for (const l of readFileSync(path, 'utf8').split('\n')) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(\\d+):(.+)$`));
        if (m) cols[+m[1]][+m[2]] = leHex(m[3]);
      }
      return cols;
    };
    const advice = loadL('/tmp/sid_zkpp_advice.txt', 'A', 53).map((c) => lagrangeToCoeff(c, K));
    const fixed = loadL('/tmp/sid_zkpp_pk.txt', 'F', 55).map((c) => lagrangeToCoeff(c, K));
    const inst = Array(N).fill(0n);
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) inst[+m[1]] = leHex(m[2]);
    }
    const instance = [lagrangeToCoeff(inst, K)];
    // queries (ordered by index): TAG:i:colindex:rotation
    const parseQ = (tag: string) => {
      const q: { col: number; rot: number }[] = [];
      for (const l of readFileSync('/tmp/sid_zkpp_cs.txt', 'utf8').split('\n')) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(-?\\d+):(-?\\d+)$`));
        if (m) q[+m[1]] = { col: +m[2], rot: +m[3] };
      }
      return q;
    };
    const xrot = (rot: number) => FpReal.mul(x, FpReal.pow(omega, BigInt(((rot % N) + N) % N)));
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const evals: bigint[] = [];
    for (const q of parseQ('IQ')) evals.push(evalPolynomial(instance[q.col], xrot(q.rot)));
    for (const q of parseQ('AQ')) evals.push(evalPolynomial(advice[q.col], xrot(q.rot)));
    for (const q of parseQ('FQ')) evals.push(evalPolynomial(fixed[q.col], xrot(q.rot)));
    let ok = 0;
    for (let i = 0; i < evals.length; i++)
      if (fe(evals[i]) === proofHex.slice((88 + i) * 64, (88 + i) * 64 + 64)) ok++;
    console.log(`EVALS instance+advice+fixed: ${ok}/${evals.length} match (offset point 88)`);
    expect(ok).toBe(evals.length);
  }, 120000);
});

describe('real ZkppCircuit create_proof — stage 7c vanishing + permutation-common evals', () => {
  it('random_eval + 56 sigma evals match proof[243..300]', () => {
    if (!existsSync('/tmp/sid_zkpp_proof.txt')) { console.log('SKIP'); return; }
    const K = 11;
    const x = leHex('8176ef85595455da940b6aa36cdd5dc7807a724b58af8ef0148af74bdb7f8517');
    const fe = (v: bigint) => [...FpReal.toBytes(v)].map((b) => b.toString(16).padStart(2, '0')).join('');
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    // vanishing random poly = rng coeffs at offset 539 (advice 371 + lookups 84 + permZ 48 + lookupZ 36).
    const rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14 + 8 * 6 + 6 * 6; i++) rng.nextScalar();
    const randomPoly = Array.from({ length: N }, () => rng.nextScalar());
    const randomEval = evalPolynomial(randomPoly, x);
    let off = 88 + 155;
    let ok = fe(randomEval) === proofHex.slice(off * 64, off * 64 + 64);
    console.log(`vanishing random_eval match: ${ok}`);
    off += 1;
    // 56 sigma evals: lagrangeToCoeff(sigma[j]) at x.
    const sigmas: bigint[][] = Array.from({ length: 56 }, () => Array(N).fill(0n));
    for (const l of readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').split('\n')) {
      const m = l.match(/^S:(\d+):(\d+):(.+)$/); if (m) sigmas[+m[1]][+m[2]] = leHex(m[3]);
    }
    let sigOk = 0;
    for (let j = 0; j < 56; j++) {
      const ev = evalPolynomial(lagrangeToCoeff(sigmas[j], K), x);
      if (fe(ev) === proofHex.slice((off + j) * 64, (off + j) * 64 + 64)) sigOk++;
    }
    console.log(`sigma evals: ${sigOk}/56 match`);
    expect(ok && sigOk === 56).toBe(true);
  }, 120000);
});

describe('real ZkppCircuit create_proof — stage 7d/7e permutation-set + lookup evals', () => {
  it('23 perm-set + 30 lookup evals match proof[300..353]', () => {
    if (!existsSync('/tmp/sid_perm_z.txt') || !existsSync('/tmp/sid_lk.txt')) { console.log('SKIP'); return; }
    const K = 11;
    const x = leHex('8176ef85595455da940b6aa36cdd5dc7807a724b58af8ef0148af74bdb7f8517');
    const beta = leHex('86e847078d289eabd9a203471b4964c924080266dda9710142fbaa8f0c0c2837');
    const gamma = leHex('cc5a8802603ccdca3f9dd351ec911c1f03d181e5ebcfc58635a9133dd4d8bf13');
    const omega = omegaForSize(K);
    const fe = (v: bigint) => [...FpReal.toBytes(v)].map((b) => b.toString(16).padStart(2, '0')).join('');
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const xw = FpReal.mul(x, omega);
    const xwLast = FpReal.mul(x, FpReal.pow(omega, BigInt(N - 6)));
    const xInv = FpReal.mul(x, FpReal.pow(omega, BigInt(N - 1)));
    const evals: bigint[] = [];
    // permutation sets: blinded Z (grand product + 5 rng blinding), rng offset 455 per stage 5b.
    const zdump = readFileSync('/tmp/sid_perm_z.txt', 'utf8').split('\n').filter((s) => s.startsWith('DUMP_PERM_Z=')).map((s) => s.slice(12));
    let rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14; i++) rng.nextScalar();
    for (let c = 0; c < 8; c++) {
      const z = Array.from({ length: N }, (_, i) => leHex(zdump[c].slice(i * 64, i * 64 + 64)));
      for (let r = N - 5; r < N; r++) z[r] = rng.nextScalar();
      rng.nextScalar();
      const zc = lagrangeToCoeff(z, K);
      evals.push(evalPolynomial(zc, x), evalPolynomial(zc, xw));
      if (c < 7) evals.push(evalPolynomial(zc, xwLast));
    }
    // lookups: blinded product Z + A'/S' coeffs.
    const parseCol = (h: string) => Array.from({ length: N }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const lk = readFileSync('/tmp/sid_lk.txt', 'utf8').split('\n'), lk2 = readFileSync('/tmp/sid_lk2.txt', 'utf8').split('\n');
    const cins = lk.filter((s) => s.startsWith('DUMP_LK_CIN=')).map((s) => parseCol(s.slice(12)));
    const ctabs = lk.filter((s) => s.startsWith('DUMP_LK_CTAB=')).map((s) => parseCol(s.slice(13)));
    const aps = lk2.filter((s) => s.startsWith('DUMP_LK_AP=')).map((s) => parseCol(s.slice(11)));
    const sps = lk2.filter((s) => s.startsWith('DUMP_LK_SP=')).map((s) => parseCol(s.slice(11)));
    rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14 + 8 * 6; i++) rng.nextScalar();
    for (let l = 0; l < 6; l++) {
      const lp = Array.from({ length: N }, (_, i) => FpReal.mul(FpReal.mul(FpReal.add(cins[l][i], beta), FpReal.add(ctabs[l][i], gamma)), FpReal.inv(FpReal.mul(FpReal.add(aps[l][i], beta), FpReal.add(sps[l][i], gamma)))));
      const z = new Array(N).fill(0n); z[0] = 1n;
      for (let i = 1; i < N - 5; i++) z[i] = FpReal.mul(z[i - 1], lp[i - 1]);
      for (let i = N - 5; i < N; i++) z[i] = rng.nextScalar();
      rng.nextScalar();
      const zc = lagrangeToCoeff(z, K), ac = lagrangeToCoeff(aps[l], K), sc = lagrangeToCoeff(sps[l], K);
      evals.push(evalPolynomial(zc, x), evalPolynomial(zc, xw), evalPolynomial(ac, x), evalPolynomial(ac, xInv), evalPolynomial(sc, x));
    }
    let ok = 0;
    const base = 88 + 155 + 1 + 56;
    for (let i = 0; i < evals.length; i++) if (fe(evals[i]) === proofHex.slice((base + i) * 64, (base + i) * 64 + 64)) ok++;
    console.log(`perm-set+lookup evals: ${ok}/${evals.length} match (base point ${base})`);
    expect(ok).toBe(evals.length);
  }, 120000);
});

describe('real ZkppCircuit create_proof — stage 8a multiopen x1/x2', () => {
  it('transcript through eval section squeezes Rust x_1, x_2', () => {
    if (!existsSync('/tmp/sid_zkpp_proof.txt')) { console.log('SKIP'); return; }
    const fe = (v: bigint) => [...FpReal.toBytes(v)].map((b) => b.toString(16).padStart(2, '0')).join('');
    const gLagrange: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gLagrange[+m[1]] = Vesta.fromBytes(fromHexBytes(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHexBytes(m[1])) as { x: bigint; y: bigint };
    }
    const vkRepr = leHex(readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').match(/PK_VK_REPR=(\w+)/)![1]);
    const inst = Array(N).fill(0n);
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/); if (m) inst[+m[1]] = leHex(m[2]);
    }
    const instCommit = Vesta.add(Vesta.msm(inst, gLagrange), Vesta.scalarMul(1n, w));
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const point = (i: number) => Vesta.fromBytes(fromHexBytes(proofHex.slice(i * 64, i * 64 + 64)));
    const scalarAt = (i: number) => leHex(proofHex.slice(i * 64, i * 64 + 64));
    const t = new Transcript();
    t.commonScalar(vkRepr);
    t.commonPoint(instCommit as any);
    for (let i = 0; i < 53; i++) t.commonPoint(point(i) as any);
    t.squeezeChallenge();
    for (let i = 53; i < 65; i++) t.commonPoint(point(i) as any);
    t.squeezeChallenge(); t.squeezeChallenge();
    for (let i = 65; i < 80; i++) t.commonPoint(point(i) as any);
    t.squeezeChallenge(); // y
    for (let i = 80; i < 88; i++) t.commonPoint(point(i) as any);
    t.squeezeChallenge(); // x
    for (let i = 88; i < 88 + 265; i++) t.commonScalar(scalarAt(i)); // 265 eval scalars
    const x1 = t.squeezeChallenge();
    const x2 = t.squeezeChallenge();
    console.log(`X1: ${fe(x1).slice(0, 12)} (rust 1a8f8a1abc67)  X2: ${fe(x2).slice(0, 12)} (rust b352d5717bb8)`);
    expect(fe(x1)).toBe('1a8f8a1abc6745b0704f6b3cfd7495a21fbe609d4d2759b9e9beefc81663003f');
    expect(fe(x2)).toBe('b352d5717bb87dfcc1d2d151f8b9a2a49fa88ded7d44019c3e2090fba088e228');
  }, 120000);
});
