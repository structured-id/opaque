/**
 * Incomplete point addition gate, a port of halo2_gadgets 0.5
 * `ecc::chip::add_incomplete` (configure only: this circuit never assigns it,
 * but its gate is part of the constraint system).
 */
import {
  add,
  mul,
  sub,
  type Column,
  type Selector,
} from "../../halo2/expression.js";
import type { ConstraintSystem } from "../../halo2/constraint-system.js";

export class AddIncompleteConfig {
  private constructor(
    readonly q: Selector,
    readonly xP: Column<"Advice">,
    readonly yP: Column<"Advice">,
    readonly xQr: Column<"Advice">,
    readonly yQr: Column<"Advice">,
  ) {}

  static configure(
    meta: ConstraintSystem,
    xP: Column<"Advice">,
    yP: Column<"Advice">,
    xQr: Column<"Advice">,
    yQr: Column<"Advice">,
  ): AddIncompleteConfig {
    for (const c of [xP, yP, xQr, yQr]) meta.enableEquality(c);
    const config = new AddIncompleteConfig(meta.selector(), xP, yP, xQr, yQr);
    meta.createGate("incomplete addition", (m) => {
      const q = m.querySelector(config.q);
      const xp = m.queryAdvice(xP, 0);
      const yp = m.queryAdvice(yP, 0);
      const xq = m.queryAdvice(xQr, 0);
      const yq = m.queryAdvice(yQr, 0);
      const xr = m.queryAdvice(xQr, 1);
      const yr = m.queryAdvice(yQr, 1);
      const dy = sub(yp, yq);
      const poly1 = sub(
        mul(mul(add(add(xr, xq), xp), sub(xp, xq)), sub(xp, xq)),
        mul(dy, dy),
      );
      const poly2 = sub(
        mul(add(yr, yq), sub(xp, xq)),
        mul(sub(yp, yq), sub(xq, xr)),
      );
      return [mul(q, poly1), mul(q, poly2)];
    });
    return config;
  }
}
