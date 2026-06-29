/**
 * halo2 gate-expression evaluator for the pure-TS quotient. Gates are dumped from
 * the real ConstraintSystem as s-expression JSON (see dump_cs_for_ts):
 *   ["c","<le-hex>"]  constant
 *   ["f",col,rot] / ["a",col,rot] / ["i",col,rot]  fixed/advice/instance query
 *   ["n",e]  negate   ["+",a,b]  sum   ["*",a,b]  product   ["s",e,"<le-hex>"]  scale
 * Rotations wrap within the domain of size n.
 */
import { Fp } from "./field.js";

export type Ast =
  | ["c", string]
  | ["f", number, number]
  | ["a", number, number]
  | ["i", number, number]
  | ["n", Ast]
  | ["+", Ast, Ast]
  | ["*", Ast, Ast]
  | ["s", Ast, string];

export interface EvalCtx {
  advice: bigint[][];
  fixed: bigint[][];
  instance: bigint[][];
  n: number;
  /** Rotation scale: 1 over the base domain, qpd (= extended_n/n) over a coset. */
  rotScale?: number;
}

export const leHex = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2)
    v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};

export function evalAst(node: Ast, row: number, ctx: EvalCtx): bigint {
  switch (node[0]) {
    case "c":
      return leHex(node[1]);
    case "f":
      return ctx.fixed[node[1]][
        (((row + node[2] * (ctx.rotScale ?? 1)) % ctx.n) + ctx.n) % ctx.n
      ];
    case "a":
      return ctx.advice[node[1]][
        (((row + node[2] * (ctx.rotScale ?? 1)) % ctx.n) + ctx.n) % ctx.n
      ];
    case "i":
      return ctx.instance[node[1]][
        (((row + node[2] * (ctx.rotScale ?? 1)) % ctx.n) + ctx.n) % ctx.n
      ];
    case "n":
      return Fp.sub(0n, evalAst(node[1], row, ctx));
    case "+":
      return Fp.add(evalAst(node[1], row, ctx), evalAst(node[2], row, ctx));
    case "*":
      return Fp.mul(evalAst(node[1], row, ctx), evalAst(node[2], row, ctx));
    case "s":
      return Fp.mul(evalAst(node[1], row, ctx), leHex(node[2]));
    default:
      throw new Error("bad ast node");
  }
}

/**
 * Compile a gate AST into a JIT-friendly closure that evaluates it at a row,
 * inlining the whole expression (no per-node recursion/switch). Byte-identical
 * to evalAst; ~2x faster on the hot quotient/coset loop. rotScale is baked in.
 */
export function compileAst(
  node: Ast,
  rotScale: number,
  n: number,
): (row: number, ctx: EvalCtx) => bigint {
  const idx = (rot: number) => `((row+${rot * rotScale})%${n}+${n})%${n}`;
  const gen = (nd: Ast): string => {
    switch (nd[0]) {
      case "c":
        return `${leHex(nd[1]).toString()}n`;
      case "f":
        return `c.fixed[${nd[1]}][${idx(nd[2])}]`;
      case "a":
        return `c.advice[${nd[1]}][${idx(nd[2])}]`;
      case "i":
        return `c.instance[${nd[1]}][${idx(nd[2])}]`;
      case "n":
        return `F.sub(0n,${gen(nd[1])})`;
      case "+":
        return `F.add(${gen(nd[1])},${gen(nd[2])})`;
      case "*":
        return `F.mul(${gen(nd[1])},${gen(nd[2])})`;
      case "s":
        return `F.mul(${gen(nd[1])},${leHex(nd[2]).toString()}n)`;
      default:
        throw new Error("bad ast node");
    }
  };
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  const fn = new Function("row", "c", "F", `return ${gen(node)}`) as (
    row: number,
    ctx: EvalCtx,
    F: typeof Fp,
  ) => bigint;
  return (row, ctx) => fn(row, ctx, Fp);
}
