/**
 * Row evaluation of many expressions at once, as halo2's `GraphEvaluator`
 * does for the quotient: the expressions become one DAG with every
 * structurally equal subexpression computed once (sums and products keyed
 * without regard to operand order, `a + (−b)` as one subtraction, constant
 * operands folded), run as a flat register program for each row. The values
 * are the field values the trees denote; only the number of operations
 * changes.
 */
import { Fp } from "../field.js";
import type { Expression } from "./expression.js";

const ADD = 0;
const SUB = 1;
const MUL = 2;
const NEG = 3;

export interface RowProgram {
  /** Register count; constants sit in registers that no row overwrites. */
  readonly regs: number;
  readonly constRegs: Int32Array;
  readonly constVals: bigint[];
  /** One load per distinct (column kind, column, rotation). */
  readonly leafRegs: Int32Array;
  readonly leafKinds: Uint8Array;
  readonly leafCols: Int32Array;
  readonly leafRots: Int32Array;
  /** `[op, dst, a, b]` quadruples. */
  readonly code: Int32Array;
  /** The register holding each root expression. */
  readonly outputs: Int32Array;
}

const KIND = { fixed: 0, advice: 1, instance: 2 } as const;

export function compileRows(roots: Expression[]): RowProgram {
  const memo = new Map<string, number>();
  // Per register: how it is produced, for folding negations and constants.
  const opOf: number[] = [];
  const argOf: number[] = [];
  const constOf = new Map<number, bigint>();
  const constRegs: number[] = [];
  const constVals: bigint[] = [];
  const leafRegs: number[] = [];
  const leafKinds: number[] = [];
  const leafCols: number[] = [];
  const leafRots: number[] = [];
  const code: number[] = [];
  let regs = 0;

  const constant = (v: bigint): number => {
    const key = `c${v}`;
    let r = memo.get(key);
    if (r === undefined) {
      r = regs++;
      memo.set(key, r);
      opOf[r] = -1;
      constOf.set(r, v);
      constRegs.push(r);
      constVals.push(v);
    }
    return r;
  };
  const leaf = (kind: number, column: number, rotation: number): number => {
    const key = `l${kind}:${column}:${rotation}`;
    let r = memo.get(key);
    if (r === undefined) {
      r = regs++;
      memo.set(key, r);
      opOf[r] = -1;
      leafRegs.push(r);
      leafKinds.push(kind);
      leafCols.push(column);
      leafRots.push(rotation);
    }
    return r;
  };
  const emit = (op: number, a: number, b: number): number => {
    const commutes = op === ADD || op === MUL;
    const [x, y] = commutes && b < a ? [b, a] : [a, b];
    const key = `${op}:${x}:${y}`;
    let r = memo.get(key);
    if (r === undefined) {
      r = regs++;
      memo.set(key, r);
      opOf[r] = op;
      argOf[r] = x;
      code.push(op, r, x, y);
    }
    return r;
  };
  const negate = (a: number): number => {
    const c = constOf.get(a);
    if (c !== undefined) return constant(Fp.neg(c));
    if (opOf[a] === NEG) return argOf[a];
    return emit(NEG, a, a);
  };
  const add = (a: number, b: number): number => {
    const ca = constOf.get(a);
    const cb = constOf.get(b);
    if (ca !== undefined && cb !== undefined) return constant(Fp.add(ca, cb));
    if (ca === 0n) return b;
    if (cb === 0n) return a;
    if (opOf[b] === NEG) return emit(SUB, a, argOf[b]);
    if (opOf[a] === NEG) return emit(SUB, b, argOf[a]);
    return emit(ADD, a, b);
  };
  const mul = (a: number, b: number): number => {
    const ca = constOf.get(a);
    const cb = constOf.get(b);
    if (ca !== undefined && cb !== undefined) return constant(Fp.mul(ca, cb));
    if (ca === 0n || cb === 0n) return constant(0n);
    if (ca === 1n) return b;
    if (cb === 1n) return a;
    return emit(MUL, a, b);
  };
  const walk = (e: Expression): number => {
    switch (e.k) {
      case "constant":
        return constant(e.v);
      case "selector":
        throw new Error("selectors are compressed before proving");
      case "fixed":
        return leaf(KIND.fixed, e.q.column, e.q.rotation);
      case "advice":
        return leaf(KIND.advice, e.q.column, e.q.rotation);
      case "instance":
        return leaf(KIND.instance, e.q.column, e.q.rotation);
      case "negated":
        return negate(walk(e.a));
      case "sum":
        return add(walk(e.a), walk(e.b));
      case "product":
        return mul(walk(e.a), walk(e.b));
      case "scaled":
        return mul(walk(e.a), constant(e.f));
    }
  };
  const outputs = Int32Array.from(roots, walk);
  // Drop what no output needs (a negation folded into a subtraction, say),
  // walking the code backwards from the outputs.
  const live = new Uint8Array(regs);
  for (const r of outputs) live[r] = 1;
  const keep = new Uint8Array(code.length / 4);
  for (let q = code.length / 4 - 1; q >= 0; q--) {
    if (!live[code[4 * q + 1]]) continue;
    keep[q] = 1;
    live[code[4 * q + 2]] = 1;
    live[code[4 * q + 3]] = 1;
  }
  const liveCode = code.filter((_, i) => keep[i >> 2]);
  const leafKeep = leafRegs.map((r) => live[r]);
  return {
    regs,
    constRegs: Int32Array.from(constRegs),
    constVals,
    leafRegs: Int32Array.from(leafRegs.filter((_, i) => leafKeep[i])),
    leafKinds: Uint8Array.from(leafKinds.filter((_, i) => leafKeep[i])),
    leafCols: Int32Array.from(leafCols.filter((_, i) => leafKeep[i])),
    leafRots: Int32Array.from(leafRots.filter((_, i) => leafKeep[i])),
    code: Int32Array.from(liveCode),
    outputs,
  };
}

/** A program bound to column values over a domain of `size` rows (a power of two). */
export interface RowRunner {
  /** Evaluate every expression at `row`; results in `regs[outputs[i]]`. */
  run(row: number): void;
  readonly regs: bigint[];
}

/**
 * Bind `p` to columns; a rotation moves `rotScale` rows (1 on the domain,
 * 2^(extended_k − k) on the extended coset), wrapping around.
 */
export function bindRows(
  p: RowProgram,
  cols: { fixed: bigint[][]; advice: bigint[][]; instance: bigint[][] },
  size: number,
  rotScale: number,
): RowRunner {
  const regs = new Array<bigint>(p.regs).fill(0n);
  p.constRegs.forEach((r, i) => (regs[r] = p.constVals[i]));
  const byKind = [cols.fixed, cols.advice, cols.instance];
  const leafArrays = Array.from(
    p.leafRegs,
    (_, i) => byKind[p.leafKinds[i]][p.leafCols[i]],
  );
  const leafShift = Int32Array.from(p.leafRots, (r) => r * rotScale);
  const mask = size - 1;
  const { code, leafRegs } = p;
  const leaves = leafRegs.length;
  const len = code.length;
  return {
    regs,
    run(row: number): void {
      for (let i = 0; i < leaves; i++)
        regs[leafRegs[i]] = leafArrays[i][(row + leafShift[i]) & mask];
      for (let pc = 0; pc < len; pc += 4) {
        const a = regs[code[pc + 2]];
        const b = regs[code[pc + 3]];
        switch (code[pc]) {
          case ADD:
            regs[code[pc + 1]] = Fp.add(a, b);
            break;
          case SUB:
            regs[code[pc + 1]] = Fp.sub(a, b);
            break;
          case MUL:
            regs[code[pc + 1]] = Fp.mul(a, b);
            break;
          default:
            regs[code[pc + 1]] = Fp.neg(a);
        }
      }
    },
  };
}
