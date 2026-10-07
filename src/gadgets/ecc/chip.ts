/**
 * The ECC chip of halo2_gadgets 0.5 (`ecc::chip::EccChip`, anchored-base
 * version) over ten advice columns: configure in the reference's order, and
 * the two instructions this circuit uses (witness a non-identity point,
 * multiply it by a base-field element).
 */
import type { Column } from "../../halo2/expression.js";
import type { ConstraintSystem } from "../../halo2/constraint-system.js";
import type { AssignedCell, Layouter } from "../../halo2/layouter.js";
import type { Point } from "../../curve.js";
import type { LookupRangeCheckConfig } from "../lookup-range-check.js";
import { AddConfig } from "./add.js";
import { AddIncompleteConfig } from "./add-incomplete.js";
import { MulConfig } from "./mul.js";
import {
  configureMulFixedBaseField,
  configureMulFixedFull,
  configureMulFixedShort,
  MulFixedConfig,
} from "./mul-fixed.js";
import type { EccPoint, NonIdentityEccPoint } from "./point.js";
import { WitnessPointConfig } from "./witness-point.js";

export class EccConfig {
  private constructor(
    readonly advices: Column<"Advice">[],
    readonly witnessPoint: WitnessPointConfig,
    readonly mul: MulConfig,
    readonly lookup: LookupRangeCheckConfig,
  ) {}

  static configure(
    meta: ConstraintSystem,
    advices: Column<"Advice">[],
    lagrangeCoeffs: Column<"Fixed">[],
    rangeCheck: LookupRangeCheckConfig,
  ): EccConfig {
    const a = advices;
    const witnessPoint = WitnessPointConfig.configure(meta, a[0], a[1]);
    const addIncomplete = AddIncompleteConfig.configure(
      meta,
      a[0],
      a[1],
      a[2],
      a[3],
    );
    const add = AddConfig.configure(
      meta,
      a[0],
      a[1],
      a[2],
      a[3],
      a[4],
      a[5],
      a[6],
      a[7],
      a[8],
    );
    const mul = MulConfig.configure(meta, add, rangeCheck, a);
    const mulFixed = MulFixedConfig.configure(
      meta,
      lagrangeCoeffs,
      a[4],
      a[5],
      add,
      addIncomplete,
    );
    configureMulFixedFull(meta, mulFixed);
    configureMulFixedShort(meta, mulFixed);
    configureMulFixedBaseField(meta, [a[6], a[7], a[8]]);
    return new EccConfig(advices, witnessPoint, mul, rangeCheck);
  }
}

export class EccChip {
  constructor(readonly config: EccConfig) {}

  /** `NonIdentityPoint::new`: witness `value` in its own region. */
  witnessNonIdentity(
    layouter: Layouter,
    value: Point | undefined,
  ): NonIdentityEccPoint {
    return layouter.assignRegion((region) =>
      this.config.witnessPoint.pointNonId(value, 0, region),
    );
  }

  /** `[scalar]base` for a base-field `scalar` cell (`ScalarVar::from_base`). */
  mul(
    layouter: Layouter,
    scalar: AssignedCell,
    base: NonIdentityEccPoint,
  ): EccPoint {
    return this.config.mul.assign(layouter, scalar, base);
  }
}
