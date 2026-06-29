/**
 * ZkppCircuit witness assembly: password -> 53x2048 advice grid, byte-exact against
 * the real halo2 circuit. Places every gadget region:
 *   A — password-policy compliance (cols 0-10)
 *   B — history diff-accumulator + Poseidon chain (cols 11-21)
 *   C — HashToCurve(password) H_p + Pedersen binding M = H_p + [r]G2 via fixed-base
 *       mul (cols 22-37, 42, 44, 50-51) and its Poseidon chains
 *   D — breach Bloom non-membership: bit-decomposition + index slices (cols 39-41)
 *
 * Verified cell-for-cell vs the Rust advice dump (tests/zkpp-advice-coverage.test.ts:
 * 3903/3903 non-zero cells byte-exact). Returns the witness advice WITHOUT the
 * prover blinding rows (create_proof fills advice[unusable..] with CounterRng).
 */
import { Fp } from "../field.js";
import { Pallas } from "../curve.js";
import { gadgetAWitness, type PolicyParams } from "./gadget-a.js";
import { gadgetBDiffAcc } from "./gadget-b.js";
import { hashBits, breachHash } from "./gadget-d.js";
import {
  permuteWithCells,
  poseidonHash2,
  bytesToFieldElements,
} from "../poseidon.js";
import {
  fixedBaseWindows,
  fixedBaseMul,
  fixedBaseUs,
  completeAdd,
} from "./ecc-chip.js";
import { hashToCurveOutside } from "../hash-to-curve.js";
import { G2 } from "../binding.js";

const N = 2048;
const CAP = 2n << 64n; // Poseidon ConstantLength<2> capacity (domain) lane

/**
 * Assemble the full ZkppCircuit advice witness for `passwordBytes` with binding
 * scalar `r` and password `policy`. The returned 53x2048 grid is byte-exact vs the
 * circuit; blinding rows are left zero for the prover to fill.
 */
export interface Witness {
  /** 53x2048 advice grid (blinding rows left zero for the prover). */
  advice: bigint[][];
  /** Public instance column: [policy-compliant, M.x, M.y, 0, ...] (M = commitment). */
  instance: bigint[];
}

export function buildAdvice(
  passwordBytes: number[],
  r: bigint,
  policy: PolicyParams,
): Witness {
  const cols: bigint[][] = Array.from({ length: 53 }, () =>
    Array<bigint>(N).fill(0n),
  );
  const put = (c: number, row: number, v: bigint): void => {
    cols[c][row] = Fp.mod(v);
  };

  // gadget_a: policy witness cols 0-9 (rows 0-127) + col10[128] compliance flag.
  const wa = gadgetAWitness(passwordBytes, policy);
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
  aCols.forEach((col, c) => col.forEach((v, row) => put(c, row, BigInt(v))));
  if (wa.compliant) put(10, 128, 1n);

  // gadget_b diff-acc: cols 11-16.
  const pNew = Array.from({ length: 128 }, (_, i) =>
    i < passwordBytes.length ? BigInt(passwordBytes[i]) : 0n,
  );
  const wb = gadgetBDiffAcc(pNew, []);
  pNew.forEach((v, row) => put(11, row, v));
  wb.diff.forEach((v, row) => put(13, row, v));
  wb.acc.forEach((v, row) => put(14, row, v));
  put(15, 127, wb.diffInv);

  // Poseidon Pow5 region placer: 37-row permutation + input (R3) / pad (R4) regions.
  const placePow5 = (
    base: number,
    start: number,
    a: bigint,
    b: bigint,
  ): void => {
    const c = permuteWithCells([a, b, CAP]);
    for (let i = 0; i < 37; i++) {
      put(base, start + i, c.states[i][0]);
      put(base + 1, start + i, c.states[i][1]);
      put(base + 2, start + i, c.states[i][2]);
    }
    for (let j = 0; j < 28; j++) put(base + 3, start + 4 + j, c.partialSbox[j]);
    if (start >= 4) {
      put(base + 2, start - 4, CAP);
      put(base + 2, start - 3, CAP);
      put(base + 2, start - 1, CAP);
      put(base, start - 2, a);
      put(base, start - 1, a);
    }
  };

  // gadget_b Poseidon chain H(0,0)->... cols 18-21.
  const gbStarts = [4, 45, 86, 127, 168, 209];
  let h = 0n;
  gbStarts.forEach((s, i) => {
    const prev = i === 0 ? 0n : h;
    placePow5(18, s, prev, 0n);
    h = poseidonHash2(prev, 0n);
  });

  // gadget_c + gadget_d Poseidon chains over the password field elements: cols 34-37 / 46-49.
  const pwBuf = new Uint8Array(128);
  pwBuf.set(Uint8Array.from(passwordBytes));
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

  // gadget_c fixed-base mul [r]G2: windows cols 22-27, final complete-add row 86.
  const windows = fixedBaseWindows(r);
  const fb = fixedBaseMul(windows);
  const us = fixedBaseUs(85);
  for (let w = 0; w < 85; w++) {
    const p = fb.points[w] as { x: bigint; y: bigint };
    put(22, 1 + w, p.x);
    put(23, 1 + w, p.y);
    put(26, 1 + w, BigInt(windows[w]));
    put(27, 1 + w, us[w][windows[w]]); // u^2 = y_p + z magnitude check
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
  const rG2 = Pallas.scalarMul(r, G2) as { x: bigint; y: bigint };
  put(22, 0, hp.x);
  put(23, 0, hp.y);
  // fixed-base mul's last step is a COMPLETE add (point[84] + accs[83]); result [r]G2 at row 87.
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
  // commitment M = H_p + [r]G2 (complete add), rows 88-89.
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
  const bits = hashBits(breachHash(passwordBytes, 128));
  let recomp = 0n;
  for (let i = 0; i < 255; i++) {
    put(39, i, BigInt(bits[i]));
    recomp += BigInt(bits[i]) << BigInt(i);
    put(40, i, recomp);
  }
  // bloom-index region (k=3 indices, index_bits=8): col 39 = bit, col 41 = per-index acc.
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

  // password-as-field-element reconstruction: col 50 = byte (reversed), 51 = BE Horner acc.
  let pacc = 0n;
  for (let j = 0; j < passwordBytes.length; j++) {
    const b = passwordBytes[passwordBytes.length - 1 - j];
    put(50, 21 + j, BigInt(b));
    pacc = pacc * 256n + BigInt(b);
    put(51, 21 + j, pacc);
  }
  put(51, 128, h); // gadget_b final history-commitment hash copy

  // gadget_c binding input copies + H_p decomposition / curve-equation cells.
  put(38, 0, fes[0]);
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
  const hpY2 = Fp.add(Fp.mul(Fp.square(hp.x), hp.x), 5n); // y^2 = x^3 + 5
  put(33, 7, hpY2);
  put(33, 8, hpY2);

  // Public instance: policy-compliant flag + the commitment M = H_p + [r]G2.
  const instance = new Array<bigint>(N).fill(0n);
  instance[0] = wa.compliant ? 1n : 0n;
  instance[1] = Fp.mod(ca.xr);
  instance[2] = Fp.mod(ca.yr);

  return { advice: cols, instance };
}
