/**
 * Witnessing a curve point, a port of halo2_gadgets 0.5
 * `ecc::chip::witness_point`. The gate trees follow the reference exactly,
 * including `(q_point * x) * curve_eqn`, which the verifying key pins.
 */
import {
  constant,
  mul,
  sub,
  type Column,
  type Expression,
  type Selector,
} from "../../halo2/expression.js";
import type {
  ConstraintSystem,
  VirtualCells,
} from "../../halo2/constraint-system.js";
import type { Region } from "../../halo2/layouter.js";
import type { Point } from "../../curve.js";
import { NonIdentityEccPoint } from "./point.js";

export class WitnessPointConfig {
  private constructor(
    readonly qPoint: Selector,
    readonly qPointNonId: Selector,
    readonly x: Column<"Advice">,
    readonly y: Column<"Advice">,
  ) {}

  static configure(
    meta: ConstraintSystem,
    x: Column<"Advice">,
    y: Column<"Advice">,
  ): WitnessPointConfig {
    const config = new WitnessPointConfig(
      meta.selector(),
      meta.selector(),
      x,
      y,
    );
    const curveEqn = (m: VirtualCells): Expression => {
      const xq = m.queryAdvice(x, 0);
      const yq = m.queryAdvice(y, 0);
      // y^2 - x^2·x - b
      return sub(sub(mul(yq, yq), mul(mul(xq, xq), xq)), constant(5));
    };
    meta.createGate("witness point", (m) => {
      const q = m.querySelector(config.qPoint);
      const xq = m.queryAdvice(x, 0);
      const yq = m.queryAdvice(y, 0);
      return [mul(mul(q, xq), curveEqn(m)), mul(mul(q, yq), curveEqn(m))];
    });
    meta.createGate("witness non-identity point", (m) => {
      const q = m.querySelector(config.qPointNonId);
      return [mul(q, curveEqn(m))];
    });
    return config;
  }

  /** Witness a non-identity point in a row of `region`. */
  pointNonId(
    value: Point | undefined,
    offset: number,
    region: Region,
  ): NonIdentityEccPoint {
    region.enableSelector(this.qPointNonId, offset);
    if (value === null) throw new Error("witnessed point is the identity");
    const x = region.assignAdvice(this.x, offset, () => value?.x);
    const y = region.assignAdvice(this.y, offset, () => value?.y);
    return new NonIdentityEccPoint(x, y);
  }
}
