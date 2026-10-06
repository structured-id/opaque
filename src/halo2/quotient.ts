/**
 * The quotient of halo2_proofs 0.3 `create_proof`, split by coset class.
 *
 * The extended coset is ζ·⟨ω_ext⟩ with 2^extended_k = Q·n points. Its rows
 * j ≡ r (mod Q) are s_r·⟨ω_n⟩ with s_r = ζ·ω_ext^r, so a polynomial of
 * degree < n is evaluated on class r by one size-n FFT of cᵢ·s_rⁱ, and every
 * rotation of the circuit moves a whole multiple of Q rows, staying inside
 * the class. Each class is therefore evaluated on its own: its constraint
 * values folded with y, divided by the vanishing polynomial (constant on the
 * class), and interpolated back to Σ_m c_{i+nm}·(s_rⁿ)^m. The coefficient
 * form is recovered by a size-Q DFT per index i, so the result equals the
 * reference's extended-domain FFT exactly, whichever order the classes run.
 */
import { Fp } from "../field.js";
import { bestFft, omegaForSize } from "../fft.js";
import { ZETA } from "../domain.js";
import type { ColumnType } from "./expression.js";
import { bindRows, type RowProgram } from "./evaluator.js";

/** One class of the extended coset. */
export class CosetClass {
  readonly r: number;
  readonly k: number;
  /** s_r^i and s_r^(-i)/n for i < n. */
  private readonly pow: bigint[];
  private readonly invPow: bigint[];
  /** X at the class rows: s_r·ω_n^q. */
  readonly x: bigint[];
  /** 1 / (s_rⁿ − 1). */
  readonly tInv: bigint;
  private readonly omega: bigint;
  private readonly omegaInv: bigint;

  constructor(r: number, k: number, extendedK: number) {
    this.r = r;
    this.k = k;
    const n = 1 << k;
    const s = Fp.mul(ZETA, Fp.pow(omegaForSize(extendedK), BigInt(r)));
    const sInv = Fp.inv(s);
    const nInv = Fp.inv(BigInt(n));
    this.omega = omegaForSize(k);
    this.omegaInv = Fp.inv(this.omega);
    this.pow = new Array<bigint>(n);
    this.invPow = new Array<bigint>(n);
    this.x = new Array<bigint>(n);
    let p = 1n;
    let q = nInv;
    let x = s;
    for (let i = 0; i < n; i++) {
      this.pow[i] = p;
      this.invPow[i] = q;
      this.x[i] = x;
      p = Fp.mul(p, s);
      q = Fp.mul(q, sInv);
      x = Fp.mul(x, this.omega);
    }
    this.tInv = Fp.inv(Fp.sub(p, 1n));
  }

  /** Values of a coefficient polynomial (degree < n) at the class rows. */
  evaluate(coeffs: bigint[]): bigint[] {
    const n = this.pow.length;
    const a = new Array<bigint>(n);
    for (let i = 0; i < n; i++)
      a[i] = i < coeffs.length ? Fp.mul(coeffs[i], this.pow[i]) : 0n;
    bestFft(a, this.omega, this.k);
    return a;
  }

  /** From class values of a degree < Q·n polynomial to Σ_m c_{i+nm}·(s_rⁿ)^m. */
  interpolate(values: bigint[]): bigint[] {
    const a = values.slice();
    bestFft(a, this.omegaInv, this.k);
    for (let i = 0; i < a.length; i++) a[i] = Fp.mul(a[i], this.invPow[i]);
    return a;
  }
}

/**
 * Coefficients c_0 … c_{pieces·n − 1} from the interpolated classes:
 * w_r[i] = Σ_m d_m·ω_Q^(rm) with d_m = c_{i+nm}·ζ^(nm), so d is the inverse
 * size-Q DFT of (w_r[i])_r.
 */
export function combineClasses(
  ws: bigint[][],
  k: number,
  pieces: number,
): bigint[] {
  const n = 1 << k;
  const classes = ws.length;
  const logQ = Math.log2(classes);
  const omegaQInv = Fp.inv(omegaForSize(logQ));
  // table[m][r] = ω_Q^(−rm) · ζ^(−nm) / Q
  const zetaNInv = Fp.inv(Fp.pow(ZETA, BigInt(n)));
  const qInv = Fp.inv(BigInt(classes));
  const table: bigint[][] = [];
  let zm = qInv;
  for (let m = 0; m < pieces; m++) {
    const row: bigint[] = [];
    const wm = Fp.pow(omegaQInv, BigInt(m));
    let v = zm;
    for (let r = 0; r < classes; r++) {
      row.push(v);
      v = Fp.mul(v, wm);
    }
    table.push(row);
    zm = Fp.mul(zm, zetaNInv);
  }
  const out = new Array<bigint>(pieces * n);
  for (let i = 0; i < n; i++)
    for (let m = 0; m < pieces; m++) {
      const row = table[m];
      let acc = 0n;
      for (let r = 0; r < classes; r++)
        acc = Fp.add(acc, Fp.mul(ws[r][i], row[r]));
      out[i + n * m] = acc;
    }
  return out;
}

/** A column the permutation argument covers. */
export interface PermColumn {
  readonly type: ColumnType;
  readonly index: number;
}

/** What the quotient needs from the constraint system; fixed per key. */
export interface QuotientShape {
  readonly k: number;
  readonly extendedK: number;
  readonly blindingFactors: number;
  /** Columns per permutation product (degree − 2). */
  readonly chunkLen: number;
  readonly permColumns: PermColumn[];
  /** Gate polynomials first, then every lookup's input and table expressions. */
  readonly program: RowProgram;
  readonly gateCount: number;
  /** Output indices (after the gates) of each lookup's input and table expressions. */
  readonly lookupSlots: { input: number[]; table: number[] }[];
  /** δ, the permutation's coset generator. */
  readonly delta: bigint;
}

/** Fixed, permutation and Lagrange-basis polynomials, in coefficient form. */
export interface KeyPolys {
  readonly fixed: bigint[][];
  readonly sigma: bigint[][];
  readonly l0: bigint[];
  readonly lLast: bigint[];
  readonly lBlind: bigint[];
}

/** The key polynomials evaluated on one class. */
export interface ClassKey {
  readonly cls: CosetClass;
  readonly fixed: bigint[][];
  readonly sigma: bigint[][];
  readonly l0: bigint[];
  readonly lLast: bigint[];
  readonly lBlind: bigint[];
}

export function classKey(cls: CosetClass, key: KeyPolys): ClassKey {
  return {
    cls,
    fixed: key.fixed.map((p) => cls.evaluate(p)),
    sigma: key.sigma.map((p) => cls.evaluate(p)),
    l0: cls.evaluate(key.l0),
    lLast: cls.evaluate(key.lLast),
    lBlind: cls.evaluate(key.lBlind),
  };
}

/** The witness polynomials of one proof, in coefficient form. */
export interface ProofPolys {
  readonly advice: bigint[][];
  readonly instance: bigint[][];
  readonly permZ: bigint[][];
  readonly lookups: { ap: bigint[]; sp: bigint[]; z: bigint[] }[];
}

export interface QuotientChallenges {
  readonly theta: bigint;
  readonly beta: bigint;
  readonly gamma: bigint;
  readonly y: bigint;
}

/**
 * The folded constraints of one class divided by t(X), interpolated
 * (see {@link CosetClass.interpolate}). The fold order is the reference's:
 * gates, permutation, lookups.
 */
export function quotientClass(
  shape: QuotientShape,
  ck: ClassKey,
  polys: ProofPolys,
  ch: QuotientChallenges,
): bigint[] {
  const { cls } = ck;
  const n = 1 << shape.k;
  const mask = n - 1;
  const bf = shape.blindingFactors;
  const { theta, beta, gamma, y } = ch;
  const advice = polys.advice.map((p) => cls.evaluate(p));
  const instance = polys.instance.map((p) => cls.evaluate(p));
  const zs = polys.permZ.map((p) => cls.evaluate(p));
  const lookups = polys.lookups.map((l) => ({
    ap: cls.evaluate(l.ap),
    sp: cls.evaluate(l.sp),
    z: cls.evaluate(l.z),
  }));
  const rows = bindRows(
    shape.program,
    { fixed: ck.fixed, advice, instance },
    n,
    1,
  );
  const regs = rows.regs;
  const outs = shape.program.outputs;
  const gates = shape.gateCount;
  const permCols = shape.permColumns.map((c) =>
    c.type === "Advice"
      ? advice[c.index]
      : c.type === "Fixed"
        ? ck.fixed[c.index]
        : instance[c.index],
  );
  const chunkLen = shape.chunkLen;
  // beta·δ^g, the per-column factor of X in the identity permutation
  const betaDelta = [beta];
  for (let i = 1; i < permCols.length; i++)
    betaDelta.push(Fp.mul(betaDelta[i - 1], shape.delta));
  const foldTheta = (at: number[]) => {
    let acc = 0n;
    for (const i of at) acc = Fp.add(Fp.mul(acc, theta), regs[outs[gates + i]]);
    return acc;
  };
  const { l0, lLast, lBlind, sigma } = ck;
  const X = cls.x;
  const out = new Array<bigint>(n);
  for (let q = 0; q < n; q++) {
    const next = (q + 1) & mask;
    const prev = (q - 1) & mask;
    const last = (q - (bf + 1)) & mask;
    let acc = 0n;
    rows.run(q);
    for (let g = 0; g < gates; g++) acc = Fp.add(Fp.mul(acc, y), regs[outs[g]]);
    const push = (v: bigint) => (acc = Fp.add(Fp.mul(acc, y), v));
    const active = Fp.sub(1n, Fp.add(lLast[q], lBlind[q]));
    push(Fp.mul(l0[q], Fp.sub(1n, zs[0][q])));
    const zl = zs[zs.length - 1][q];
    push(Fp.mul(lLast[q], Fp.sub(Fp.mul(zl, zl), zl)));
    for (let c = 1; c < zs.length; c++)
      push(Fp.mul(l0[q], Fp.sub(zs[c][q], zs[c - 1][last])));
    for (let c = 0; c < zs.length; c++) {
      let left = zs[c][next];
      let right = zs[c][q];
      const end = Math.min((c + 1) * chunkLen, permCols.length);
      for (let g = c * chunkLen; g < end; g++) {
        const v = permCols[g][q];
        left = Fp.mul(
          left,
          Fp.add(Fp.add(v, Fp.mul(beta, sigma[g][q])), gamma),
        );
        right = Fp.mul(
          right,
          Fp.add(Fp.add(v, Fp.mul(betaDelta[g], X[q])), gamma),
        );
      }
      push(Fp.mul(active, Fp.sub(left, right)));
    }
    for (let i = 0; i < lookups.length; i++) {
      const { z, ap: A, sp: S } = lookups[i];
      const cin = foldTheta(shape.lookupSlots[i].input);
      const ctab = foldTheta(shape.lookupSlots[i].table);
      push(Fp.mul(l0[q], Fp.sub(1n, z[q])));
      push(Fp.mul(lLast[q], Fp.sub(Fp.mul(z[q], z[q]), z[q])));
      push(
        Fp.mul(
          active,
          Fp.sub(
            Fp.mul(Fp.mul(z[next], Fp.add(A[q], beta)), Fp.add(S[q], gamma)),
            Fp.mul(Fp.mul(z[q], Fp.add(cin, beta)), Fp.add(ctab, gamma)),
          ),
        ),
      );
      const aMinusS = Fp.sub(A[q], S[q]);
      push(Fp.mul(l0[q], aMinusS));
      push(Fp.mul(Fp.mul(active, aMinusS), Fp.sub(A[q], A[prev])));
    }
    out[q] = Fp.mul(acc, cls.tInv);
  }
  return cls.interpolate(out);
}
