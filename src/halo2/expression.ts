/**
 * Circuit expressions over the Pallas base field, mirroring halo2_proofs 0.3
 * `plonk::Expression` node for node: the verifying key's transcript
 * representative hashes their Debug text, so the tree shape (not only the
 * value) must match the reference.
 */
import { Fp } from "../field.js";

export type ColumnType = "Advice" | "Fixed" | "Instance";

export interface Column<T extends ColumnType = ColumnType> {
  readonly index: number;
  readonly type: T;
}

/** A selector; simple selectors may be compressed with others into one fixed column. */
export interface Selector {
  readonly index: number;
  readonly simple: boolean;
}

export interface Query {
  readonly index: number;
  readonly column: number;
  readonly rotation: number;
}

export type Expression =
  | { readonly k: "constant"; readonly v: bigint }
  | { readonly k: "selector"; readonly s: Selector }
  | { readonly k: "fixed"; readonly q: Query }
  | { readonly k: "advice"; readonly q: Query }
  | { readonly k: "instance"; readonly q: Query }
  | { readonly k: "negated"; readonly a: Expression }
  | { readonly k: "sum"; readonly a: Expression; readonly b: Expression }
  | { readonly k: "product"; readonly a: Expression; readonly b: Expression }
  | { readonly k: "scaled"; readonly a: Expression; readonly f: bigint };

export const constant = (v: bigint | number): Expression => ({
  k: "constant",
  v: Fp.mod(BigInt(v)),
});

export const neg = (a: Expression): Expression => ({ k: "negated", a });

export function add(a: Expression, b: Expression): Expression {
  if (containsSimpleSelector(a) || containsSimpleSelector(b))
    throw new Error("attempted to use a simple selector in an addition");
  return { k: "sum", a, b };
}

export function sub(a: Expression, b: Expression): Expression {
  if (containsSimpleSelector(a) || containsSimpleSelector(b))
    throw new Error("attempted to use a simple selector in a subtraction");
  return { k: "sum", a, b: neg(b) };
}

export function mul(a: Expression, b: Expression): Expression {
  if (containsSimpleSelector(a) && containsSimpleSelector(b))
    throw new Error(
      "attempted to multiply two expressions containing simple selectors",
    );
  return { k: "product", a, b };
}

/** `a * f` for a field constant `f` (Rust `Mul<F>`). */
export const scale = (a: Expression, f: bigint): Expression => ({
  k: "scaled",
  a,
  f: Fp.mod(f),
});

/** Sum of a non-empty list, left to right. */
export const sumAll = (xs: Expression[]): Expression =>
  xs.reduce((acc, x) => add(acc, x));

export interface Evaluator<T> {
  constant(v: bigint): T;
  selector(s: Selector): T;
  fixed(q: Query): T;
  advice(q: Query): T;
  instance(q: Query): T;
  negated(a: T): T;
  sum(a: T, b: T): T;
  product(a: T, b: T): T;
  scaled(a: T, f: bigint): T;
}

export function evaluate<T>(e: Expression, ev: Evaluator<T>): T {
  switch (e.k) {
    case "constant":
      return ev.constant(e.v);
    case "selector":
      return ev.selector(e.s);
    case "fixed":
      return ev.fixed(e.q);
    case "advice":
      return ev.advice(e.q);
    case "instance":
      return ev.instance(e.q);
    case "negated":
      return ev.negated(evaluate(e.a, ev));
    case "sum":
      return ev.sum(evaluate(e.a, ev), evaluate(e.b, ev));
    case "product":
      return ev.product(evaluate(e.a, ev), evaluate(e.b, ev));
    case "scaled":
      return ev.scaled(evaluate(e.a, ev), e.f);
  }
}

export function degree(e: Expression): number {
  switch (e.k) {
    case "constant":
      return 0;
    case "selector":
    case "fixed":
    case "advice":
    case "instance":
      return 1;
    case "negated":
    case "scaled":
      return degree(e.a);
    case "sum":
      return Math.max(degree(e.a), degree(e.b));
    case "product":
      return degree(e.a) + degree(e.b);
  }
}

export function containsSimpleSelector(e: Expression): boolean {
  switch (e.k) {
    case "selector":
      return e.s.simple;
    case "negated":
    case "scaled":
      return containsSimpleSelector(e.a);
    case "sum":
    case "product":
      return containsSimpleSelector(e.a) || containsSimpleSelector(e.b);
    default:
      return false;
  }
}

/** The one simple selector in `e`, if any; two in one expression is an error. */
export function extractSimpleSelector(e: Expression): Selector | null {
  const op = (a: Selector | null, b: Selector | null): Selector | null => {
    if (a && b)
      throw new Error("two simple selectors cannot be in the same expression");
    return a ?? b;
  };
  switch (e.k) {
    case "selector":
      return e.s.simple ? e.s : null;
    case "negated":
    case "scaled":
      return extractSimpleSelector(e.a);
    case "sum":
    case "product":
      return op(extractSimpleSelector(e.a), extractSimpleSelector(e.b));
    default:
      return null;
  }
}

/** A field element as pasta_curves Debug prints it: big-endian hex. */
export function fieldDebug(v: bigint): string {
  return "0x" + Fp.mod(v).toString(16).padStart(64, "0");
}

/** `Rotation(n)`. */
export const rotationDebug = (r: number): string => `Rotation(${r})`;

const queryDebug = (name: string, q: Query): string =>
  `${name} { query_index: ${q.index}, column_index: ${q.column}, rotation: ${rotationDebug(q.rotation)} }`;

/** Rust `{:?}` of an expression. */
export function expressionDebug(e: Expression): string {
  switch (e.k) {
    case "constant":
      return `Constant(${fieldDebug(e.v)})`;
    case "selector":
      return `Selector(Selector(${e.s.index}, ${e.s.simple}))`;
    case "fixed":
      return queryDebug("Fixed", e.q);
    case "advice":
      return queryDebug("Advice", e.q);
    case "instance":
      return queryDebug("Instance", e.q);
    case "negated":
      return `Negated(${expressionDebug(e.a)})`;
    case "sum":
      return `Sum(${expressionDebug(e.a)}, ${expressionDebug(e.b)})`;
    case "product":
      return `Product(${expressionDebug(e.a)}, ${expressionDebug(e.b)})`;
    case "scaled":
      return `Scaled(${expressionDebug(e.a)}, ${fieldDebug(e.f)})`;
  }
}

/** `Column { index: 3, column_type: Advice }`. */
export const columnDebug = (c: Column): string =>
  `Column { index: ${c.index}, column_type: ${c.type} }`;
