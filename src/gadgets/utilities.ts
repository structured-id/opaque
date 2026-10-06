/** Gate helpers of halo2_gadgets 0.5 `utilities`, node for node. */
import {
  add,
  constant,
  mul,
  sub,
  type Expression,
} from "../halo2/expression.js";

/** `word · (1 - word) · (2 - word) ⋯ (range - 1 - word)`. */
export function rangeCheck(word: Expression, range: number): Expression {
  let acc = word;
  for (let i = 1; i < range; i++) acc = mul(acc, sub(constant(i), word));
  return acc;
}

export const boolCheck = (value: Expression): Expression =>
  rangeCheck(value, 2);

/** `a·b + (1 - a)·c`. */
export const ternary = (
  a: Expression,
  b: Expression,
  c: Expression,
): Expression => add(mul(a, b), mul(sub(constant(1), a), c));
