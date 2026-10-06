/**
 * Overflow check of a variable-base scalar multiplication by a base-field
 * element, a port of halo2_gadgets 0.5 `ecc::chip::mul::overflow`.
 */
import { Fp, FQ_MODULUS } from "../../field.js";
import {
  add,
  constant,
  mul,
  sub,
  type Column,
  type Selector,
} from "../../halo2/expression.js";
import type { ConstraintSystem } from "../../halo2/constraint-system.js";
import {
  vzip,
  type AssignedCell,
  type Layouter,
} from "../../halo2/layouter.js";
import type { LookupRangeCheckConfig } from "../lookup-range-check.js";
import { inv0 } from "./add.js";

/** `t_q`: the Pallas scalar field modulus is `2^254 + t_q`. */
export const T_Q = FQ_MODULUS - (1n << 254n);

export class MulOverflowConfig {
  private constructor(
    readonly qMulOverflow: Selector,
    readonly lookup: LookupRangeCheckConfig,
    readonly advices: [Column<"Advice">, Column<"Advice">, Column<"Advice">],
  ) {}

  static configure(
    meta: ConstraintSystem,
    lookup: LookupRangeCheckConfig,
    advices: [Column<"Advice">, Column<"Advice">, Column<"Advice">],
  ): MulOverflowConfig {
    for (const a of advices) meta.enableEquality(a);
    const config = new MulOverflowConfig(meta.selector(), lookup, advices);
    meta.createGate("overflow checks", (m) => {
      const q = m.querySelector(config.qMulOverflow);
      const one = constant(1);
      const twoPow124 = constant(1n << 124n);
      const twoPow130 = mul(twoPow124, constant(1n << 6n));
      const z0 = m.queryAdvice(advices[0], -1);
      const z130 = m.queryAdvice(advices[0], 0);
      const eta = m.queryAdvice(advices[0], 1);
      const k254 = m.queryAdvice(advices[1], -1);
      const alpha = m.queryAdvice(advices[1], 0);
      const sMinusLo130 = m.queryAdvice(advices[1], 1);
      const s = m.queryAdvice(advices[2], 0);
      const sCheck = sub(s, add(alpha, mul(k254, twoPow130)));
      const tQ = constant(T_Q);
      const recovery = sub(sub(z0, alpha), tQ);
      const loZero = mul(k254, sub(z130, twoPow124));
      const sMinusLo130Check = mul(k254, sMinusLo130);
      const canonicity = mul(
        mul(sub(one, k254), sub(one, mul(z130, eta))),
        sMinusLo130,
      );
      return [sCheck, recovery, loZero, sMinusLo130Check, canonicity].map((p) =>
        mul(q, p),
      );
    });
    return config;
  }

  /** `zs` is the running sum `[z_0, ..., z_255]` of the multiplication. */
  overflowCheck(
    layouter: Layouter,
    alpha: AssignedCell,
    zs: AssignedCell[],
  ): void {
    const k254 = zs[254];
    const sVal = vzip([alpha.value, k254.value], (a, k) =>
      Fp.add(a, Fp.mul(k, Fp.square(1n << 65n))),
    );
    const s = layouter.assignRegion((region) =>
      region.assignAdvice(this.advices[0], 0, () => sVal),
    );
    const decomposed = this.lookup.copyCheck(layouter, s, 13, false);
    const sMinusLo130 = decomposed[decomposed.length - 1];

    layouter.assignRegion((region) => {
      region.enableSelector(this.qMulOverflow, 1);
      zs[0].copyAdvice(region, this.advices[0], 0);
      zs[130].copyAdvice(region, this.advices[0], 1);
      const eta = vzip([zs[130].value], (z) => inv0(z));
      region.assignAdvice(this.advices[0], 2, () => eta);
      zs[254].copyAdvice(region, this.advices[1], 0);
      alpha.copyAdvice(region, this.advices[1], 1);
      sMinusLo130.copyAdvice(region, this.advices[1], 2);
      s.copyAdvice(region, this.advices[2], 1);
    });
  }
}
