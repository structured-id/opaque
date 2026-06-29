// Advice assembly coverage: place every verified region into the 53×2048 grid and
// measure how much of the real circuit advice we reproduce byte-exact. Reads the
// /tmp dump (measurement, not CI) — skips cleanly if absent.
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { Fp } from "../src/field.js";
import { gadgetAWitness, type PolicyParams } from "../src/circuit/gadget-a.js";
import { gadgetBDiffAcc } from "../src/circuit/gadget-b.js";
import { hashBits, breachHash } from "../src/circuit/gadget-d.js";
import {
  permuteWithCells,
  poseidonHash2,
  bytesToFieldElements,
} from "../src/poseidon.js";
import {
  fixedBaseWindows,
  fixedBaseMul,
  fixedBaseUs,
  completeAdd,
} from "../src/circuit/ecc-chip.js";
import { hashToCurveOutside } from "../src/hash-to-curve.js";
import { Pallas } from "../src/curve.js";
import { G2 } from "../src/binding.js";
import { CounterRng } from "../src/prover.js";

const N = 2048;
const fe = (v: bigint) =>
  [...Fp.toBytes(v)].map((x) => x.toString(16).padStart(2, "0")).join("");
const CE: PolicyParams = {
  minLength: 8,
  minUpper: 1,
  minLower: 1,
  minDigit: 1,
  minSymbol: 0,
};

describe("advice assembly coverage vs real circuit dump", () => {
  it("reports byte-exact coverage of the 53×2048 advice", () => {
    const path = "/tmp/sid_zkpp_advice.txt";
    if (!existsSync(path)) {
      console.log("SKIP: no dump");
      return;
    }
    const dump: Record<string, string> = {};
    for (const l of readFileSync(path, "utf8").split("\n")) {
      const m = l.match(/^A:(\d+):(\d+):(.+)$/);
      if (m) dump[`${m[1]},${m[2]}`] = m[3];
    }
    const grid: Record<string, string> = {};
    const put = (c: number, r: number, v: bigint) => {
      grid[`${c},${r}`] = fe(v);
    };

    // gadget_a: cols 0-9 (rows 0-127) + col10[128] compliance.
    const pwArr = [...new TextEncoder().encode("Str0ngP@ss")];
    const wa = gadgetAWitness(pwArr, CE);
    const aCols = [
      wa.byte,
      wa.active,
      wa.isU,
      wa.isL,
      wa.isD,
      wa.isS,
      wa.accU,
      wa.accL,
      wa.accD,
      wa.accS,
    ];
    aCols.forEach((col, c) => col.forEach((v, r) => put(c, r, BigInt(v))));
    if (wa.compliant) put(10, 128, 1n);

    // gadget_b diff-acc: cols 11-16.
    const pNew = Array.from({ length: 128 }, (_, i) =>
      i < pwArr.length ? BigInt(pwArr[i]) : 0n,
    );
    const wb = gadgetBDiffAcc(pNew, []);
    pNew.forEach((v, r) => put(11, r, v));
    wb.diff.forEach((v, r) => put(13, r, v));
    wb.acc.forEach((v, r) => put(14, r, v));
    put(15, 127, wb.diffInv);

    // Pow5 placement helper.
    const placePow5 = (base: number, start: number, a: bigint, b: bigint) => {
      const c = permuteWithCells([a, b, 2n << 64n]);
      for (let i = 0; i < 37; i++) {
        put(base, start + i, c.states[i][0]);
        put(base + 1, start + i, c.states[i][1]);
        put(base + 2, start + i, c.states[i][2]);
      }
      for (let j = 0; j < 28; j++)
        put(base + 3, start + 4 + j, c.partialSbox[j]);
      // Pow5 input region (R3, len 1) + pad region (R4, len 3) before the 37-row
      // permutation: capacity lane (base+2) at start-4/-3/-1; input lane a
      // (base+0) at start-2/-1. b lane is absorbed in-permutation, not here.
      if (start >= 4) {
        const CAP = 2n << 64n;
        put(base + 2, start - 4, CAP);
        put(base + 2, start - 3, CAP);
        put(base + 2, start - 1, CAP);
        put(base, start - 2, a);
        put(base, start - 1, a);
      }
    };
    // gadget_b poseidon chain H(0,0)→... cols 18-21.
    const gbStarts = [4, 45, 86, 127, 168, 209];
    let h = 0n;
    gbStarts.forEach((s, i) => {
      const prev = i === 0 ? 0n : h;
      placePow5(18, s, prev, 0n);
      h = poseidonHash2(prev, 0n);
    });
    // gadget_c + gadget_d poseidon chains over password fes, cols 34-37 / 46-49.
    const pwBuf = new Uint8Array(128);
    pwBuf.set(new TextEncoder().encode("Str0ngP@ss"));
    const fes = bytesToFieldElements(pwBuf);
    const chainStarts = [4, 45, 86, 127];
    for (const base of [34, 46]) {
      let u = 0n;
      chainStarts.forEach((s, i) => {
        const a = i === 0 ? fes[0] : u;
        const b = fes[i + 1];
        placePow5(base, s, a, b);
        u = poseidonHash2(a, b);
      });
    }
    // gadget_c fixed-base mul cols 22-27 (R46 start=1) + complete-add row88.
    const windows = fixedBaseWindows(3n);
    const fb = fixedBaseMul(windows);
    const us = fixedBaseUs(85);
    for (let w = 0; w < 85; w++) {
      const p = fb.points[w] as { x: bigint; y: bigint };
      put(22, 1 + w, p.x);
      put(23, 1 + w, p.y);
      put(26, 1 + w, BigInt(windows[w]));
      put(27, 1 + w, us[w][windows[w]]); // halo2 fixed-base u (u^2 = y_p + z)
      if (w === 0) {
        put(24, 1, 0n);
        put(25, 1, 0n);
      } else {
        const a = fb.accs[w - 1] as { x: bigint; y: bigint };
        put(24, 1 + w, a.x);
        put(25, 1 + w, a.y);
      }
    }
    const hp = hashToCurveOutside(pwBuf).point as { x: bigint; y: bigint };
    const rG2 = Pallas.scalarMul(3n, G2) as { x: bigint; y: bigint };
    put(22, 0, hp.x);
    put(23, 0, hp.y); // H_p.y at the binding input row
    // Fixed-base mul's final step is a COMPLETE add (halo2 handles the last window
    // completely): point[84] + accs[83] at row 86, result [r]G2 at row 87.
    const p84 = fb.points[84] as { x: bigint; y: bigint };
    const a83 = fb.accs[83] as { x: bigint; y: bigint };
    const ca86 = completeAdd(p84.x, p84.y, a83.x, a83.y);
    put(22, 86, p84.x);
    put(23, 86, p84.y);
    put(24, 86, a83.x);
    put(25, 86, a83.y);
    put(26, 86, ca86.lambda);
    put(27, 86, ca86.alpha);
    put(28, 86, ca86.beta);
    put(29, 86, ca86.gamma);
    put(30, 86, ca86.delta);
    put(24, 87, ca86.xr);
    put(25, 87, ca86.yr);
    const ca = completeAdd(hp.x, hp.y, rG2.x, rG2.y);
    put(22, 88, hp.x);
    put(23, 88, hp.y);
    put(24, 88, rG2.x);
    put(25, 88, rG2.y);
    put(26, 88, ca.lambda);
    put(27, 88, ca.alpha);
    put(28, 88, ca.beta);
    put(29, 88, ca.gamma);
    put(30, 88, ca.delta);
    put(24, 89, ca.xr);
    put(25, 89, ca.yr);

    // gadget_d bit-decomposition cols 39-40.
    const bh = breachHash(pwArr, 128);
    const bits = hashBits(bh);
    let recomp = 0n;
    for (let i = 0; i < 255; i++) {
      put(39, i, BigInt(bits[i]));
      recomp += BigInt(bits[i]) << BigInt(i);
      put(40, i, recomp);
    }
    // bloom-index region (k=3 indices, index_bits=8): re-decompose the low 24 hash
    // bits, col 39 = bit, col 41 = per-index running LSB accumulator (the index),
    // rows 255.. (24 rows).
    let irow = 255;
    for (let i = 0; i < 3; i++) {
      let acc = 0;
      for (let l = 0; l < 8; l++) {
        const bit = bits[i * 8 + l];
        put(39, irow, BigInt(bit));
        acc |= bit << l;
        put(41, irow, BigInt(acc));
        irow++;
      }
    }
    // Password-as-field-element reconstruction (cols 50 = byte in reverse order,
    // 51 = running little-endian accumulator), rows 21.. ; col 38 row 0 holds the
    // assembled fe (the HashToCurve poseidon input).
    let pacc = 0n;
    for (let j = 0; j < pwArr.length; j++) {
      const b = pwArr[pwArr.length - 1 - j];
      put(50, 21 + j, BigInt(b));
      pacc = pacc * 256n + BigInt(b); // big-endian Horner over reversed bytes
      put(51, 21 + j, pacc);
    }
    put(38, 0, fes[0]);
    // gadget_c binding input copies (H_p coords / pw fe) + H_p.x low-byte cells.
    put(32, 0, fes[0]);
    put(32, 5, hp.x);
    put(32, 7, hp.x);
    put(33, 6, hp.y);
    const hpxB = [...Fp.toBytes(hp.x)];
    put(42, 0, BigInt(hpxB[0]));
    put(42, 1, BigInt(hpxB[1]));
    put(42, 2, BigInt(hpxB[2]));
    put(44, 0, 1n);
    put(44, 1, 1n);
    put(44, 2, 1n);
    put(51, 128, h); // copy of the gadget_b final history-commitment hash
    // H_p curve-equation RHS y^2 = x^3 + 5 (HashToCurve map check), cols 33 r7/8.
    const hpY2 = Fp.add(Fp.mul(Fp.square(hp.x), hp.x), 5n);
    put(33, 7, hpY2);
    put(33, 8, hpY2);

    // Blinding rows 2042-2047 (bf=5): create_proof fills advice[unusable..] column-
    // major with CounterRng(0) scalars (the first rng consumption).
    const rng = new CounterRng();
    for (let c = 0; c < 53; c++)
      for (let r = 2042; r < 2048; r++) put(c, r, rng.nextScalar());

    // Coverage: of all non-zero dump cells, how many we reproduce exactly.
    let totalNz = 0,
      matched = 0,
      wrong = 0;
    for (const [k, v] of Object.entries(dump)) {
      if (BigInt("0x" + v.match(/../g)!.reverse().join("")) === 0n) continue;
      totalNz++;
      if (grid[k] === v) matched++;
      else if (grid[k] !== undefined) wrong++;
    }
    console.log(
      `COVERAGE: ${matched}/${totalNz} non-zero cells byte-exact (${((100 * matched) / totalNz).toFixed(1)}%), wrong=${wrong}`,
    );
    // diagnostic: which columns/rows have unplaced non-zero cells
    const missCol: Record<number, { n: number; rows: number[] }> = {};
    for (const [k, v] of Object.entries(dump)) {
      if (BigInt("0x" + v.match(/../g)!.reverse().join("")) === 0n) continue;
      if (grid[k] === undefined) {
        const [c, r] = k.split(",").map(Number);
        (missCol[c] ??= { n: 0, rows: [] }).n++;
        if (missCol[c].rows.length < 10) missCol[c].rows.push(r);
      }
    }
    for (const c of Object.keys(missCol)
      .map(Number)
      .sort((a, b) => a - b))
      console.log(
        `  MISSING col ${c}: ${missCol[c].n} cells, rows e.g. ${missCol[c].rows.join(",")}`,
      );
    expect(wrong).toBe(0); // anything we DO place must be correct
    expect(matched).toBeGreaterThan(0);
  });
});
