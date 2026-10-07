// The row program must give every root the value its expression tree
// denotes at each row: random trees over random columns, with shared
// subtrees, subtractions written as `a + (−b)`, double negations, constant
// operands (0, 1, folded pairs) and rotations that wrap past either end.
import { describe, it, expect } from "vitest";
import { Fp } from "../src/field.js";
import {
  add,
  constant,
  evaluate,
  mul,
  neg,
  scale,
  sub,
  type Expression,
} from "../src/halo2/expression.js";
import { bindRows, compileRows } from "../src/halo2/evaluator.js";

let seed = 12345n;
const next = (): bigint => {
  seed =
    (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
  return seed;
};
const pick = (n: number) => Number(next() % BigInt(n));
const fe = () => Fp.mod(next() * next() * next() * next());

const SIZE = 16;
const ROT_SCALE = 2;
const cols = {
  fixed: Array.from({ length: 3 }, () => Array.from({ length: SIZE }, fe)),
  advice: Array.from({ length: 3 }, () => Array.from({ length: SIZE }, fe)),
  instance: [Array.from({ length: SIZE }, fe)],
};

let queryIndex = 0;
function leaf(): Expression {
  const kind = pick(3);
  const rotation = pick(5) - 2;
  const q = { index: queryIndex++, column: kind === 2 ? 0 : pick(3), rotation };
  return kind === 0
    ? { k: "fixed", q }
    : kind === 1
      ? { k: "advice", q }
      : { k: "instance", q };
}

function tree(depth: number, shared: Expression[]): Expression {
  if (depth === 0 || pick(5) === 0) {
    const r = pick(10);
    if (r === 0) return constant([0, 1, 5][pick(3)]);
    if (r === 1 && shared.length) return shared[pick(shared.length)];
    return leaf();
  }
  const a = tree(depth - 1, shared);
  const b = tree(depth - 1, shared);
  let e: Expression;
  switch (pick(6)) {
    case 0:
      e = add(a, b);
      break;
    case 1:
      e = sub(a, b);
      break;
    case 2:
      e = mul(a, b);
      break;
    case 3:
      e = neg(neg(a));
      break;
    case 4:
      e = scale(a, fe());
      break;
    default:
      e = add(neg(a), b);
  }
  if (pick(3) === 0) shared.push(e);
  return e;
}

const at = (col: bigint[], rot: number, row: number) =>
  col[(((row + rot * ROT_SCALE) % SIZE) + SIZE) % SIZE];

function direct(e: Expression, row: number): bigint {
  return evaluate(e, {
    constant: (v) => v,
    selector: () => {
      throw new Error("no selectors");
    },
    fixed: (q) => at(cols.fixed[q.column], q.rotation, row),
    advice: (q) => at(cols.advice[q.column], q.rotation, row),
    instance: (q) => at(cols.instance[q.column], q.rotation, row),
    negated: (a) => Fp.neg(a),
    sum: (a, b) => Fp.add(a, b),
    product: (a, b) => Fp.mul(a, b),
    scaled: (a, f) => Fp.mul(a, f),
  });
}

describe("row program", () => {
  it("evaluates random expression trees like the trees themselves", () => {
    for (let trial = 0; trial < 20; trial++) {
      const shared: Expression[] = [];
      const roots = Array.from({ length: 8 }, () => tree(5, shared));
      roots.push(
        shared[0] ?? constant(3),
        constant(0),
        sub(roots[0], roots[0]),
      );
      const prog = compileRows(roots);
      const rows = bindRows(prog, cols, SIZE, ROT_SCALE);
      for (let row = 0; row < SIZE; row++) {
        rows.run(row);
        roots.forEach((e, i) =>
          expect(rows.regs[prog.outputs[i]]).toBe(direct(e, row)),
        );
      }
    }
  });

  it("computes a repeated subexpression once", () => {
    const a = leaf();
    const b = leaf();
    const ab = mul(a, b);
    const prog = compileRows([add(ab, mul(b, a)), sub(mul(a, b), ab)]);
    // one product (operand order ignored), one sum, one subtraction
    expect(prog.code.length / 4).toBe(3);
  });
});
