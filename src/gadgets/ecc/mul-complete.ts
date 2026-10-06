/**
 * Complete-addition bits of a variable-base scalar multiplication, a port of
 * halo2_gadgets 0.5 `ecc::chip::mul::complete`.
 */
import { Fp } from "../../field.js";
import {
  add,
  constant,
  mul,
  sub,
  type Column,
  type Selector,
} from "../../halo2/expression.js";
import type { ConstraintSystem } from "../../halo2/constraint-system.js";
import { vzip, type AssignedCell, type Region } from "../../halo2/layouter.js";
import { boolCheck, ternary } from "../utilities.js";
import type { AddConfig } from "./add.js";
import { EccPoint } from "./point.js";

export class MulCompleteConfig {
  private constructor(
    readonly qMulDecomposeVar: Selector,
    readonly zComplete: Column<"Advice">,
    readonly addConfig: AddConfig,
  ) {}

  static configure(
    meta: ConstraintSystem,
    zComplete: Column<"Advice">,
    addConfig: AddConfig,
  ): MulCompleteConfig {
    meta.enableEquality(zComplete);
    const config = new MulCompleteConfig(meta.selector(), zComplete, addConfig);
    meta.createGate(
      "Decompose scalar for complete bits of variable-base mul",
      (m) => {
        const q = m.querySelector(config.qMulDecomposeVar);
        const zPrev = m.queryAdvice(zComplete, -1);
        const zNext = m.queryAdvice(zComplete, 1);
        const k = sub(zNext, mul(constant(2), zPrev));
        const bool = boolCheck(k);
        const baseY = m.queryAdvice(zComplete, 0);
        const yP = m.queryAdvice(addConfig.yP, -1);
        const ySwitch = ternary(k, sub(baseY, yP), add(baseY, yP));
        return [mul(q, bool), mul(q, ySwitch)];
      },
    );
    return config;
  }

  assignRegion(
    region: Region,
    offset: number,
    bits: (boolean | undefined)[],
    base: EccPoint,
    xA: AssignedCell,
    yA: AssignedCell,
    zIn: AssignedCell,
  ): { acc: EccPoint; zs: AssignedCell[] } {
    for (let row = 0; row < bits.length; row++)
      region.enableSelector(this.qMulDecomposeVar, 2 * row + offset + 1);
    let acc = new EccPoint(xA, yA);
    let z = zIn.copyAdvice(region, this.zComplete, offset);
    const zs: AssignedCell[] = [];
    bits.forEach((k, iter) => {
      const row = 2 * iter;
      const kv = k === undefined ? undefined : k ? 1n : 0n;
      const zVal = vzip([z.value, kv], (zv, b) => Fp.add(Fp.mul(zv, 2n), b));
      z = region.assignAdvice(this.zComplete, row + offset + 2, () => zVal);
      zs.push(z);
      const baseY = base.y.copyAdvice(region, this.zComplete, row + offset + 1);
      const yPVal =
        baseY.value === undefined || k === undefined
          ? undefined
          : k
            ? baseY.value
            : Fp.neg(baseY.value);
      const yP = region.assignAdvice(
        this.addConfig.yP,
        row + offset,
        () => yPVal,
      );
      const u = new EccPoint(base.x, yP);
      const tmp = this.addConfig.assignRegion(u, acc, row + offset, region);
      acc = this.addConfig.assignRegion(acc, tmp, row + offset + 1, region);
    });
    return { acc, zs };
  }
}
