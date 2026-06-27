// Synthesize orchestration: each gadget/chip region placed into the real ZkppCircuit
// advice columns must reproduce the full-circuit advice dump byte-exact.
import { describe, it, expect } from 'vitest';
import { Fp } from '../src/zkpp/field.js';
import { gadgetAWitness, type PolicyParams } from '../src/zkpp/circuit/gadget-a.js';
import gaPlaced from './fixtures/zkpp-gadget-a-placed.json';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fe = (v: bigint) => hex(Fp.toBytes(v));
const CE: PolicyParams = { minLength: 8, minUpper: 1, minLower: 1, minDigit: 1, minSymbol: 0 };

describe('synthesize orchestration — region R0 (gadget A policy engine)', () => {
  it('gadget_a witness reproduces full-circuit advice cols 0-9 (rows 0-127) byte-exact', () => {
    const pw = [...new TextEncoder().encode('Str0ngP@ss')];
    const w = gadgetAWitness(pw, CE);
    // Column order from PolicyEngineChip::configure: byte, active, isU, isL, isD, isS,
    // accU, accL, accD, accS.
    const myCols = [w.byte, w.active, w.isU, w.isL, w.isD, w.isS, w.accU, w.accL, w.accD, w.accS];
    for (let c = 0; c < 10; c++) {
      const got = myCols[c].map((v) => fe(BigInt(v)));
      expect(got).toEqual(gaPlaced.cols[c]);
    }
  });
});

import { gadgetBDiffAcc } from '../src/zkpp/circuit/gadget-b.js';
import gbPlaced from './fixtures/zkpp-gadget-b-placed.json';

describe('synthesize orchestration — region R26 (gadget B diff-accumulator)', () => {
  it('gadget_b diff-acc reproduces real circuit advice cols 11-16 (rows 0-127) byte-exact', () => {
    const pwBytes = [...new TextEncoder().encode('Str0ngP@ss')];
    const pNew = Array.from({ length: 128 }, (_, i) => (i < pwBytes.length ? BigInt(pwBytes[i]) : 0n));
    const w = gadgetBDiffAcc(pNew, []);
    const Z = Array(128).fill(0n);
    // col11 p_new, col12 p_old(0), col13 diff, col14 diff_acc, col15 diff_inv(@127), col16 mode(0).
    const diffInvCol = [...Array(127).fill(0n), w.diffInv];
    const myCols = [pNew, Z, w.diff, w.acc, diffInvCol, Z];
    for (let c = 0; c < 6; c++) {
      const got = myCols[c].map((v) => fe(v));
      expect(got).toEqual(gbPlaced.cols[c]);
    }
  });
});

import { permuteWithCells } from '../src/zkpp/poseidon.js';
import pow5r5 from './fixtures/zkpp-pow5-r5.json';

describe('synthesize orchestration — region R5 (Pow5 Poseidon permutation, first gadget_b hash H(0,0))', () => {
  it('permuteWithCells([0,0,2<<64]) reproduces real circuit Pow5 cols 18-21 byte-exact', () => {
    const cells = permuteWithCells([0n, 0n, 2n << 64n]);
    expect(cells.states.map((s) => fe(s[0]))).toEqual(pow5r5.st0);
    expect(cells.states.map((s) => fe(s[1]))).toEqual(pow5r5.st1);
    expect(cells.states.map((s) => fe(s[2]))).toEqual(pow5r5.st2);
    expect(cells.partialSbox.map((v) => fe(v))).toEqual(pow5r5.psb);
  });
});

import { breachHash, hashBits } from '../src/zkpp/circuit/gadget-d.js';
import gdBits from './fixtures/zkpp-gadget-d-bits.json';

const leHexToBig = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};

describe('synthesize orchestration — region R67 (gadget_d hash bit-decomposition)', () => {
  it('col39 = hashBits(breach_hash), col40 = recomposition running sum (LSB-first)', () => {
    const hash = leHexToBig(gdBits.col40[254]); // full recomposition = the hash
    // col39 = the 255 LSB-first bits of the hash.
    expect(hashBits(hash).join('')).toBe(gdBits.col39.map((h: string) => Number(leHexToBig(h))).join(''));
    // col40 = running sum of bit_i * 2^i.
    let acc = 0n;
    const recomp: bigint[] = [];
    const bits = hashBits(hash);
    for (let i = 0; i < 255; i++) {
      acc += BigInt(bits[i]) << BigInt(i);
      recomp.push(acc);
    }
    expect(recomp.map((v) => fe(v))).toEqual(gdBits.col40);
  });

  it('breach_hash matches breachHash(password, padLen) for the circuit pad length', () => {
    const hash = leHexToBig(gdBits.col40[254]);
    const pw = [...new TextEncoder().encode('Str0ngP@ss')];
    const padLens = [31, 62, 93, 124, 128];
    const match = padLens.find((p) => breachHash(pw, p) === hash);
    expect(match).toBeDefined();
  });
});

import { bytesToFieldElements } from '../src/zkpp/poseidon.js';
import pow5r34 from './fixtures/zkpp-pow5-r34.json';

describe('synthesize orchestration — region R34 (gadget_c HashToCurve Poseidon, password input)', () => {
  it('permuteWithCells([fe0,fe1,2<<64]) of packed password reproduces real circuit cols 34-37', () => {
    const pwBuf = new Uint8Array(128);
    pwBuf.set(new TextEncoder().encode('Str0ngP@ss'));
    const fes = bytesToFieldElements(pwBuf);
    const cells = permuteWithCells([fes[0], fes[1], 2n << 64n]);
    expect(cells.states.map((s) => fe(s[0]))).toEqual(pow5r34.st0);
    expect(cells.states.map((s) => fe(s[1]))).toEqual(pow5r34.st1);
    expect(cells.states.map((s) => fe(s[2]))).toEqual(pow5r34.st2);
    expect(cells.partialSbox.map((v) => fe(v))).toEqual(pow5r34.psb);
  });
});

import { hashToCurveOutside } from '../src/zkpp/hash-to-curve.js';
import { Pallas } from '../src/zkpp/curve.js';
import { G2 } from '../src/zkpp/binding.js';
import gcBind from './fixtures/zkpp-gadget-c-binding.json';

describe('synthesize orchestration — gadget_c binding (fixed-base mul r·G2 + Pedersen commitment)', () => {
  it('H_p witness + r·G2 + com = H_p + r·G2 reproduce real circuit cols 22/24/25 byte-exact', () => {
    const pwBuf = new Uint8Array(128);
    pwBuf.set(new TextEncoder().encode('Str0ngP@ss'));
    const hp = hashToCurveOutside(pwBuf).point as { x: bigint; y: bigint };
    const rG2 = Pallas.scalarMul(3n, G2) as { x: bigint; y: bigint };
    const com = Pallas.add(hp, rG2) as { x: bigint; y: bigint };
    expect(fe(hp.x)).toBe(gcBind.hp_x); // H_p NonIdentityPoint witness (col22 row0)
    expect(fe(rG2.x)).toBe(gcBind.rg2_x); // fixed-base mul result r·G2 (col24 row87)
    expect(fe(com.x)).toBe(gcBind.com_x); // com_point M.x (col24 row89)
    expect(fe(com.y)).toBe(gcBind.com_y); // com_point M.y (col25 row89)
  });
});

import { fixedBaseWindows } from '../src/zkpp/circuit/ecc-chip.js';

import fbWindows from './fixtures/zkpp-fixed-base-windows.json';

describe('synthesize orchestration — R46 fixed-base mul window decomposition (col26)', () => {
  it('fixedBaseWindows(3) reproduces real circuit col26 (85 windows) byte-exact', () => {
    expect(fixedBaseWindows(3n)).toEqual(fbWindows.col26);
  });
});

import { poseidonHash2 } from '../src/zkpp/poseidon.js';
import gbChain from './fixtures/zkpp-gadgetb-chain.json';

describe('synthesize orchestration — gadget_b Poseidon hash-chain (R9/R13/R17/R21/R25)', () => {
  it('chain H(h_prev,0) reproduces real circuit Pow5 cols18-21 for all 5 remaining hashes', () => {
    // gadget_b registration: all input fes are 0 → chain h0=H(0,0), h1=H(h0,0), ...
    const h0 = poseidonHash2(0n, 0n);
    const h1 = poseidonHash2(h0, 0n);
    const h2 = poseidonHash2(h1, 0n);
    const h3 = poseidonHash2(h2, 0n);
    const h4 = poseidonHash2(h3, 0n);
    const cases: [string, bigint][] = [
      ['R9', h0], ['R13', h1], ['R17', h2], ['R21', h3], ['R25', h4],
    ];
    for (const [name, hPrev] of cases) {
      const c = permuteWithCells([hPrev, 0n, 2n << 64n]);
      const ref = (gbChain as any)[name];
      expect(c.states.map((s) => fe(s[0])), name).toEqual(ref.st0);
      expect(c.states.map((s) => fe(s[1])), name).toEqual(ref.st1);
      expect(c.states.map((s) => fe(s[2])), name).toEqual(ref.st2);
      expect(c.partialSbox.map((v) => fe(v)), name).toEqual(ref.psb);
    }
  });
});

import gcChainP from './fixtures/zkpp-gadgetc-chain.json';

describe('synthesize orchestration — gadget_c HashToCurve Poseidon chain (R37/R40/R43)', () => {
  it('chain H(u_prev,fe_i) of packed password reproduces real circuit cols34-37', () => {
    const pwBuf = new Uint8Array(128);
    pwBuf.set(new TextEncoder().encode('Str0ngP@ss'));
    const fes = bytesToFieldElements(pwBuf); // 5 field elements
    const u0 = poseidonHash2(fes[0], fes[1]);
    const u1 = poseidonHash2(u0, fes[2]);
    const u2 = poseidonHash2(u1, fes[3]);
    const cases: [string, bigint, bigint][] = [
      ['R37', u0, fes[2]], ['R40', u1, fes[3]], ['R43', u2, fes[4]],
    ];
    for (const [name, uPrev, feNext] of cases) {
      const c = permuteWithCells([uPrev, feNext, 2n << 64n]);
      const ref = (gcChainP as any)[name];
      expect(c.states.map((s) => fe(s[0])), name).toEqual(ref.st0);
      expect(c.states.map((s) => fe(s[1])), name).toEqual(ref.st1);
      expect(c.states.map((s) => fe(s[2])), name).toEqual(ref.st2);
      expect(c.partialSbox.map((v) => fe(v)), name).toEqual(ref.psb);
    }
  });
});

import gdChainP from './fixtures/zkpp-gadgetd-chain.json';

describe('synthesize orchestration — gadget_d breach Poseidon chain (R57/R60/R63/R66)', () => {
  it('chain hashes packed password (same fes) reproducing real circuit cols46-49', () => {
    const pwBuf = new Uint8Array(128);
    pwBuf.set(new TextEncoder().encode('Str0ngP@ss'));
    const fes = bytesToFieldElements(pwBuf);
    const u0 = poseidonHash2(fes[0], fes[1]);
    const u1 = poseidonHash2(u0, fes[2]);
    const u2 = poseidonHash2(u1, fes[3]);
    const cases: [string, bigint, bigint][] = [
      ['R57', fes[0], fes[1]], ['R60', u0, fes[2]], ['R63', u1, fes[3]], ['R66', u2, fes[4]],
    ];
    for (const [name, a, b] of cases) {
      const c = permuteWithCells([a, b, 2n << 64n]);
      const ref = (gdChainP as any)[name];
      expect(c.states.map((s) => fe(s[0])), name).toEqual(ref.st0);
      expect(c.states.map((s) => fe(s[1])), name).toEqual(ref.st1);
      expect(c.states.map((s) => fe(s[2])), name).toEqual(ref.st2);
      expect(c.partialSbox.map((v) => fe(v)), name).toEqual(ref.psb);
    }
  });
});

import zinputs from './fixtures/zkpp-inputs.json';

describe('synthesize orchestration — Poseidon input cells (gadget_b/c/d fes)', () => {
  it('gadget_b col17 = zeros, gadget_c col32 / gadget_d col38 = packed password fes', () => {
    // gadget_b registration: all_fes = pack(p_old=0)+pack(salt=0) = zeros.
    expect(zinputs.gb.every((h: string) => fe(0n) === h)).toBe(true);
    // gadget_c/d input cells = bytes_to_field_elements(128-byte padded password).
    const pwBuf = new Uint8Array(128);
    pwBuf.set(new TextEncoder().encode('Str0ngP@ss'));
    const fes = bytesToFieldElements(pwBuf);
    expect(zinputs.gc.map((_: string, i: number) => fe(fes[i]))).toEqual(zinputs.gc);
    expect(zinputs.gd.map((_: string, i: number) => fe(fes[i]))).toEqual(zinputs.gd);
  });
});
