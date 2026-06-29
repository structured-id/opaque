// Quotient gate-part: 134 gates evaluated over the extended coset + Horner y-fold
// must equal the Rust gate-only folded h (DUMP_HGATES). Reads /tmp — skips in CI.
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { Fp } from '../src/field.js';
import { coeffToExtended, lagrangeToCoeff } from '../src/domain.js';
import { evalAst, leHex, type Ast, type EvalCtx } from '../src/gate-eval.js';
import { CounterRng } from '../src/prover.js';

const N = 2048;
const K = 11;
const EXTK = 14;
const EXTN = 1 << EXTK;
const QPD = EXTN / N; // 8

describe('quotient gate-part — coset gate-eval + y-fold', () => {
  it('134 gates over coset, Horner y-fold, match Rust DUMP_HGATES', () => {
    if (!existsSync('/tmp/sid_hgates.txt') || !existsSync('/tmp/sid_zkpp_cs.txt')) {
      console.log('SKIP');
      return;
    }
    const y = leHex('600dc9505e3c6df6b518db6afa47e0ae0aa8157ec0996502e5e86a1edc93920b');
    const loadLagrange = (path: string, tag: string, nc: number) => {
      const cols = Array.from({ length: nc }, () => Array(N).fill(0n));
      for (const l of readFileSync(path, 'utf8').split('\n')) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(\\d+):(.+)$`));
        if (m) cols[+m[1]][+m[2]] = leHex(m[3]);
      }
      return cols;
    };
    const advice = loadLagrange('/tmp/sid_zkpp_advice.txt', 'A', 53);
    const fixed = loadLagrange('/tmp/sid_zkpp_pk.txt', 'F', 55);
    const instance = [Array(N).fill(0n)];
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) instance[0][+m[1]] = leHex(m[2]);
    }
    // Cosets: lagrange -> coeff -> extended coset.
    const toCoset = (col: bigint[]) => coeffToExtended(lagrangeToCoeff(col, K), EXTK);
    const adviceCos = advice.map(toCoset);
    const fixedCos = fixed.map(toCoset);
    const instanceCos = instance.map(toCoset);
    const ctx: EvalCtx = {
      advice: adviceCos,
      fixed: fixedCos,
      instance: instanceCos,
      n: EXTN,
      rotScale: QPD,
    };
    const gates: Ast[] = [];
    for (const l of readFileSync('/tmp/sid_zkpp_cs.txt', 'utf8').split('\n')) {
      const m = l.match(/^GATE:\d+:\d+:(.+)$/);
      if (m) gates.push(JSON.parse(m[1]) as Ast);
    }
    // Horner y-fold (distribute_powers): acc = acc*y + gate (first gate -> highest power).
    const fe = (v: bigint) =>
      [...Fp.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    const ref = readFileSync('/tmp/sid_hgates.txt', 'utf8').trim().slice('DUMP_HGATES='.length);
    let ok = true;
    for (let i = 0; i < EXTN; i++) {
      let acc = 0n;
      for (const g of gates) acc = Fp.add(Fp.mul(acc, y), evalAst(g, i, ctx));
      if (fe(acc) !== ref.slice(i * 64, i * 64 + 64)) {
        ok = false;
        if (i < 3) console.log(`mismatch at ${i}`);
        break;
      }
    }
    console.log(`HGATES coset y-fold match: ${ok}`);
    expect(ok).toBe(true);
  }, 120000);
});

describe('quotient permutation-part — 17 perm terms over coset', () => {
  it('perm terms Horner y-fold match (HGP - HGATES·y^17)', () => {
    if (!existsSync('/tmp/sid_hgp.txt') || !existsSync('/tmp/sid_perm_z.txt')) {
      console.log('SKIP');
      return;
    }
    const beta = leHex('86e847078d289eabd9a203471b4964c924080266dda9710142fbaa8f0c0c2837');
    const gamma = leHex('cc5a8802603ccdca3f9dd351ec911c1f03d181e5ebcfc58635a9133dd4d8bf13');
    const delta = leHex('a29b7bdd20cd6c6a3656ee3ef1f3e4f59d04a512715b45bd6cab06000f7d750a');
    const y = leHex('600dc9505e3c6df6b518db6afa47e0ae0aa8157ec0996502e5e86a1edc93920b');
    const loadL = (path: string, tag: string, nc: number) => {
      const cols = Array.from({ length: nc }, () => Array(N).fill(0n));
      for (const l of readFileSync(path, 'utf8').split('\n')) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(\\d+):(.+)$`));
        if (m) cols[+m[1]][+m[2]] = leHex(m[3]);
      }
      return cols;
    };
    const advice = loadL('/tmp/sid_zkpp_advice.txt', 'A', 53);
    const fixed = loadL('/tmp/sid_zkpp_pk.txt', 'F', 55);
    const sigmas = loadL('/tmp/sid_zkpp_pk.txt', 'S', 56);
    const instance = [Array(N).fill(0n)];
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) instance[0][+m[1]] = leHex(m[2]);
    }
    // extended cosets (16384) dumped directly: l0/llast/lblind/XC.
    const loadExt = (tag: string) => {
      const a = Array(EXTN).fill(0n);
      for (const l of readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').split('\n')) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(.+)$`));
        if (m) a[+m[1]] = leHex(m[2]);
      }
      return a;
    };
    const l0 = loadExt('L0'),
      lLast = loadExt('LLAST'),
      lBlind = loadExt('LBLIND'),
      XC = loadExt('XC');
    // PERM column mapping.
    const permCol: bigint[][] = [];
    for (const l of readFileSync('/tmp/sid_zkpp_cs.txt', 'utf8').split('\n')) {
      const m = l.match(/^PERM:(\d+):(\d+):(\w+)/);
      if (m) {
        const ci = +m[2],
          ty = m[3];
        permCol[+m[1]] = ty === 'Advice' ? advice[ci] : ty === 'Fixed' ? fixed[ci] : instance[ci];
      }
    }
    // blinded perm Z (grand product + 5 rng blinding rows), threaded rng like stage 5b.
    const zdump = readFileSync('/tmp/sid_perm_z.txt', 'utf8')
      .split('\n')
      .filter((x) => x.startsWith('DUMP_PERM_Z='))
      .map((x) => x.slice(12));
    const rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14; i++) rng.nextScalar();
    const toCoset = (col: bigint[]) => coeffToExtended(lagrangeToCoeff(col, K), EXTK);
    const zCos: bigint[][] = [];
    for (let c = 0; c < 8; c++) {
      const z = Array.from({ length: N }, (_, i) => leHex(zdump[c].slice(i * 64, i * 64 + 64)));
      for (let r = N - 5; r < N; r++) z[r] = rng.nextScalar();
      rng.nextScalar(); // blind (consumed, not used here)
      zCos.push(toCoset(z));
    }
    const colCos = permCol.map(toCoset);
    const sigCos = sigmas.map(toCoset);
    const dpow = [1n];
    for (let i = 1; i < 56; i++) dpow.push(Fp.mul(dpow[i - 1], delta));
    const rot = (a: bigint[], j: number, sh: number) => a[(((j + sh) % EXTN) + EXTN) % EXTN];
    // expected perm Horner = HGP - HGATES·y^17.
    const hgp = readFileSync('/tmp/sid_hgp.txt', 'utf8').trim().slice('DUMP_HGP='.length);
    const hgates = readFileSync('/tmp/sid_hgates.txt', 'utf8').trim().slice('DUMP_HGATES='.length);
    let y17 = 1n;
    for (let i = 0; i < 17; i++) y17 = Fp.mul(y17, y);
    const fe = (v: bigint) =>
      [...Fp.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    const CHUNK = 7;
    let ok = true;
    for (let j = 0; j < EXTN; j++) {
      const exprs: bigint[] = [];
      exprs.push(Fp.mul(l0[j], Fp.sub(1n, zCos[0][j]))); // first
      exprs.push(Fp.mul(lLast[j], Fp.sub(Fp.mul(zCos[7][j], zCos[7][j]), zCos[7][j]))); // last
      for (let c = 1; c < 8; c++)
        exprs.push(Fp.mul(l0[j], Fp.sub(zCos[c][j], rot(zCos[c - 1], j, -6 * QPD)))); // chain
      const lActive = Fp.sub(1n, Fp.add(lLast[j], lBlind[j]));
      for (let c = 0; c < 8; c++) {
        let left = rot(zCos[c], j, QPD),
          right = zCos[c][j];
        for (let k = 0; k < CHUNK; k++) {
          const g = c * CHUNK + k;
          left = Fp.mul(left, Fp.add(Fp.add(colCos[g][j], Fp.mul(beta, sigCos[g][j])), gamma));
          right = Fp.mul(
            right,
            Fp.add(Fp.add(colCos[g][j], Fp.mul(Fp.mul(beta, dpow[g]), XC[j])), gamma),
          );
        }
        exprs.push(Fp.mul(lActive, Fp.sub(left, right)));
      }
      let acc = 0n;
      for (const e of exprs) acc = Fp.add(Fp.mul(acc, y), e);
      const expected = Fp.sub(
        leHex(hgp.slice(j * 64, j * 64 + 64)),
        Fp.mul(leHex(hgates.slice(j * 64, j * 64 + 64)), y17),
      );
      if (fe(acc) !== fe(expected)) {
        ok = false;
        if (j < 3)
          console.log(
            `perm mismatch at ${j}: mine=${fe(acc).slice(0, 16)} exp=${fe(expected).slice(0, 16)}`,
          );
        break;
      }
    }
    console.log(`PERM-TERMS match: ${ok}`);
    expect(ok).toBe(true);
  }, 180000);
});

describe('quotient lookup-part — 30 lookup terms over coset', () => {
  it('lookup terms Horner y-fold match (HFOLDED - HGP·y^30)', () => {
    if (
      !existsSync('/tmp/sid_lk.txt') ||
      !existsSync('/tmp/sid_lk2.txt') ||
      !existsSync('/tmp/sid_h.txt')
    ) {
      console.log('SKIP');
      return;
    }
    const beta = leHex('86e847078d289eabd9a203471b4964c924080266dda9710142fbaa8f0c0c2837');
    const gamma = leHex('cc5a8802603ccdca3f9dd351ec911c1f03d181e5ebcfc58635a9133dd4d8bf13');
    const y = leHex('600dc9505e3c6df6b518db6afa47e0ae0aa8157ec0996502e5e86a1edc93920b');
    const loadExt = (tag: string) => {
      const a = Array(EXTN).fill(0n);
      for (const l of readFileSync('/tmp/sid_zkpp_pk.txt', 'utf8').split('\n')) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(.+)$`));
        if (m) a[+m[1]] = leHex(m[2]);
      }
      return a;
    };
    const l0 = loadExt('L0'),
      lLast = loadExt('LLAST'),
      lBlind = loadExt('LBLIND');
    const parseCol = (h: string) =>
      Array.from({ length: N }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const lk = readFileSync('/tmp/sid_lk.txt', 'utf8').split('\n');
    const lk2 = readFileSync('/tmp/sid_lk2.txt', 'utf8').split('\n');
    const cins = lk.filter((x) => x.startsWith('DUMP_LK_CIN=')).map((x) => parseCol(x.slice(12)));
    const ctabs = lk.filter((x) => x.startsWith('DUMP_LK_CTAB=')).map((x) => parseCol(x.slice(13)));
    const aps = lk2.filter((x) => x.startsWith('DUMP_LK_AP=')).map((x) => parseCol(x.slice(11)));
    const sps = lk2.filter((x) => x.startsWith('DUMP_LK_SP=')).map((x) => parseCol(x.slice(11)));
    const toCoset = (col: bigint[]) => coeffToExtended(lagrangeToCoeff(col, K), EXTK);
    // compressed_input/table COSET = theta-fold of input/table EXPRESSIONS over the
    // coset (NOT coeff_to_extended of the Lagrange compression — differs when an
    // input expression has degree > 1). Build advice/fixed/instance cosets + eval.
    const theta = leHex('c65ecb9f6053f97cba1c9ebbe68c999ef0ef08d44673956d2f10cd8902739321');
    const loadLag = (path: string, tag: string, nc: number) => {
      const cols = Array.from({ length: nc }, () => Array(N).fill(0n));
      for (const l of readFileSync(path, 'utf8').split('\n')) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(\\d+):(.+)$`));
        if (m) cols[+m[1]][+m[2]] = leHex(m[3]);
      }
      return cols;
    };
    const advCos = loadLag('/tmp/sid_zkpp_advice.txt', 'A', 53).map(toCoset);
    const fixCos = loadLag('/tmp/sid_zkpp_pk.txt', 'F', 55).map(toCoset);
    const instCol = [Array(N).fill(0n)];
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) instCol[0][+m[1]] = leHex(m[2]);
    }
    const cosetCtx: EvalCtx = {
      advice: advCos,
      fixed: fixCos,
      instance: instCol.map(toCoset),
      n: EXTN,
      rotScale: QPD,
    };
    // LKIN/LKTAB expression ASTs per lookup.
    const lkin: Ast[][] = [],
      lktab: Ast[][] = [];
    for (const l of readFileSync('/tmp/sid_zkpp_cs.txt', 'utf8').split('\n')) {
      let m = l.match(/^LKIN:(\d+):(\d+):(.+)$/);
      if (m) {
        (lkin[+m[1]] ??= [])[+m[2]] = JSON.parse(m[3]) as Ast;
      }
      m = l.match(/^LKTAB:(\d+):(\d+):(.+)$/);
      if (m) {
        (lktab[+m[1]] ??= [])[+m[2]] = JSON.parse(m[3]) as Ast;
      }
    }
    const compressCoset = (exprs: Ast[]) =>
      Array.from({ length: EXTN }, (_, j) => {
        let acc = 0n;
        for (const e of exprs) acc = Fp.add(Fp.mul(acc, theta), evalAst(e, j, cosetCtx));
        return acc;
      });
    // blinded lookup Z (grand product + 5 rng blinding), threaded rng like stage 5c.
    const rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14 + 8 * 6; i++) rng.nextScalar();
    const zCos: bigint[][] = [],
      apCos: bigint[][] = [],
      spCos: bigint[][] = [],
      cinCos: bigint[][] = [],
      ctabCos: bigint[][] = [];
    for (let l = 0; l < 6; l++) {
      const lp = Array.from({ length: N }, (_, i) =>
        Fp.mul(
          Fp.mul(Fp.add(cins[l][i], beta), Fp.add(ctabs[l][i], gamma)),
          Fp.inv(Fp.mul(Fp.add(aps[l][i], beta), Fp.add(sps[l][i], gamma))),
        ),
      );
      const z = new Array(N).fill(0n);
      z[0] = 1n;
      for (let i = 1; i < N - 5; i++) z[i] = Fp.mul(z[i - 1], lp[i - 1]);
      for (let i = N - 5; i < N; i++) z[i] = rng.nextScalar();
      rng.nextScalar(); // blind
      zCos.push(toCoset(z));
      apCos.push(toCoset(aps[l]));
      spCos.push(toCoset(sps[l]));
      cinCos.push(compressCoset(lkin[l]));
      ctabCos.push(compressCoset(lktab[l]));
    }
    const rot = (a: bigint[], j: number, sh: number) => a[(((j + sh) % EXTN) + EXTN) % EXTN];
    const hlPer = readFileSync('/tmp/sid_hlper.txt', 'utf8')
      .split('\n')
      .reduce((acc, line) => {
        const m = line.match(/^DUMP_HL(\d+)=(.+)$/);
        if (m) acc[+m[1]] = m[2];
        return acc;
      }, [] as string[]);
    const fe = (v: bigint) =>
      [...Fp.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    // Each lookup's 5-expr Horner y-fold must equal its DUMP_HL{l} (lookup order
    // = cs order). e2's compressed_input/table come from the LKIN/LKTAB coset-eval.
    const perOk: boolean[] = [];
    for (let l = 0; l < 6; l++) {
      const z = zCos[l],
        A = apCos[l],
        S = spCos[l],
        cin = cinCos[l],
        ctab = ctabCos[l];
      let good = true;
      for (let j = 0; j < EXTN && good; j++) {
        const active = Fp.sub(1n, Fp.add(lLast[j], lBlind[j]));
        const e = [
          Fp.mul(l0[j], Fp.sub(1n, z[j])),
          Fp.mul(lLast[j], Fp.sub(Fp.mul(z[j], z[j]), z[j])),
          Fp.mul(
            active,
            Fp.sub(
              Fp.mul(Fp.mul(rot(z, j, QPD), Fp.add(A[j], beta)), Fp.add(S[j], gamma)),
              Fp.mul(Fp.mul(z[j], Fp.add(cin[j], beta)), Fp.add(ctab[j], gamma)),
            ),
          ),
          Fp.mul(l0[j], Fp.sub(A[j], S[j])),
          Fp.mul(Fp.mul(active, Fp.sub(A[j], S[j])), Fp.sub(A[j], rot(A, j, -QPD))),
        ];
        let acc = 0n;
        for (const ee of e) acc = Fp.add(Fp.mul(acc, y), ee);
        if (fe(acc) !== hlPer[l].slice(j * 64, j * 64 + 64)) good = false;
      }
      perOk.push(good);
    }
    console.log(`LOOKUP per-lookup match: ${perOk.map((b, i) => `${i}:${b}`).join(' ')}`);
    expect(perOk.every((b) => b)).toBe(true);
  }, 180000);
});

import { extendedToCoeff, vanishingTInv, divideByVanishing } from '../src/domain.js';

describe('quotient h — /vanishing + extended_to_coeff', () => {
  it('HFOLDED / t(X) -> coeff matches Rust DUMP_HPOLY', () => {
    if (!existsSync('/tmp/sid_hpoly.txt')) { console.log('SKIP'); return; }
    const lines = readFileSync('/tmp/sid_hpoly.txt', 'utf8').split('\n');
    const hfold = lines.find((x) => x.startsWith('DUMP_HFOLDED='))!.slice('DUMP_HFOLDED='.length);
    const hpoly = lines.find((x) => x.startsWith('DUMP_HPOLY='))!.slice('DUMP_HPOLY='.length);
    const HFOLDED = Array.from({ length: EXTN }, (_, i) => leHex(hfold.slice(i * 64, i * 64 + 64)));
    const tInv = vanishingTInv(K, EXTK);
    const hCoset = divideByVanishing(HFOLDED, tInv);
    const hCoeff = extendedToCoeff(hCoset, K, EXTK, QPD);
    const fe = (v: bigint) => [...Fp.toBytes(v)].map((x) => x.toString(16).padStart(2, '0')).join('');
    let ok = hCoeff.length === hpoly.length / 64;
    for (let i = 0; i < hCoeff.length && ok; i++) if (fe(hCoeff[i]) !== hpoly.slice(i * 64, i * 64 + 64)) { ok = false; console.log(`hpoly mismatch ${i}`); }
    console.log(`HPOLY match: ${ok} (len ${hCoeff.length})`);
    expect(ok).toBe(true);
  }, 120000);
});

import { Vesta } from '../src/curve.js';

describe('quotient h — split + commit', () => {
  it('8 h-piece commitments match Rust proof[80..88]', () => {
    if (!existsSync('/tmp/sid_hpoly.txt') || !existsSync('/tmp/sid_zkpp_proof.txt')) { console.log('SKIP'); return; }
    const fromHex = (h: string) => Uint8Array.from(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
    const g: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync('/tmp/sid_zkpp_srs.txt', 'utf8').split('\n')) {
      let m = l.match(/^G:(\d+):(.+)$/);
      if (m) g[+m[1]] = Vesta.fromBytes(fromHex(m[2])) as { x: bigint; y: bigint };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHex(m[1])) as { x: bigint; y: bigint };
    }
    const hpoly = readFileSync('/tmp/sid_hpoly.txt', 'utf8').split('\n').find((x) => x.startsWith('DUMP_HPOLY='))!.slice('DUMP_HPOLY='.length);
    const hCoeff = Array.from({ length: EXTN }, (_, i) => leHex(hpoly.slice(i * 64, i * 64 + 64)));
    // rng: advice 371 + lookups permuted 84 + permZ 48 + lookupZ 36 + vanishing(2048 coeffs + 1 blind) = 2588, then 8 h blinds.
    const rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14 + 8 * 6 + 6 * 6 + (N + 1); i++) rng.nextScalar();
    const proofHex = readFileSync('/tmp/sid_zkpp_proof.txt', 'utf8').split('\n')[1];
    const hx = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    let ok = 0;
    for (let p = 0; p < 8; p++) {
      const piece = hCoeff.slice(p * N, (p + 1) * N);
      const blind = rng.nextScalar();
      const c = hx(Vesta.toBytes(Vesta.add(Vesta.msm(piece, g), Vesta.scalarMul(blind, w))));
      if (c === proofHex.slice((80 + p) * 64, (80 + p) * 64 + 64)) ok++;
    }
    console.log(`H-PIECE-COMMIT: ${ok}/8 match proof`);
    expect(ok).toBe(8);
  }, 120000);
});
