/**
 * Variable-base scalar multiplication by a base-field element, a port of
 * halo2_gadgets 0.5 `ecc::chip::mul` (anchored-base circuit version).
 */
import { Fp } from "../../field.js";
import {
  add,
  mul,
  scale,
  sub,
  type Column,
  type Selector,
} from "../../halo2/expression.js";
import type { ConstraintSystem } from "../../halo2/constraint-system.js";
import {
  vzip,
  type AssignedCell,
  type Layouter,
  type Region,
} from "../../halo2/layouter.js";
import type { LookupRangeCheckConfig } from "../lookup-range-check.js";
import { boolCheck, ternary } from "../utilities.js";
import type { AddConfig } from "./add.js";
import { MulCompleteConfig } from "./mul-complete.js";
import { MulIncompleteConfig } from "./mul-incomplete.js";
import { MulOverflowConfig, T_Q } from "./mul-overflow.js";
import { EccPoint, type NonIdentityEccPoint } from "./point.js";

const NUM_BITS = 255;
const NUM_COMPLETE_BITS = 3;
const INCOMPLETE_LEN = NUM_BITS - 1 - NUM_COMPLETE_BITS;
const INCOMPLETE_HI_LEN = Math.floor(INCOMPLETE_LEN / 2);
const INCOMPLETE_LO_LEN = INCOMPLETE_LEN - INCOMPLETE_HI_LEN;

/** Big-endian bits of `k = alpha + t_q` (unreduced), 255 of them. */
function decompose(alpha: bigint | undefined): (boolean | undefined)[] {
  if (alpha === undefined) return new Array(NUM_BITS).fill(undefined);
  const k = alpha + T_Q;
  const bits: boolean[] = [];
  for (let i = 0; i < NUM_BITS; i++) bits.push(((k >> BigInt(i)) & 1n) === 1n);
  return bits.reverse();
}

export class MulConfig {
  private constructor(
    readonly qMulLsb: Selector,
    readonly addConfig: AddConfig,
    readonly hi: MulIncompleteConfig,
    readonly lo: MulIncompleteConfig,
    readonly complete: MulCompleteConfig,
    readonly overflow: MulOverflowConfig,
  ) {}

  static configure(
    meta: ConstraintSystem,
    addConfig: AddConfig,
    lookup: LookupRangeCheckConfig,
    a: Column<"Advice">[],
  ): MulConfig {
    const hi = MulIncompleteConfig.configure(
      meta,
      INCOMPLETE_HI_LEN,
      a[9],
      a[3],
      a[0],
      a[1],
      a[4],
      a[5],
    );
    const lo = MulIncompleteConfig.configure(
      meta,
      INCOMPLETE_LO_LEN,
      a[6],
      a[7],
      a[0],
      a[1],
      a[8],
      a[2],
    );
    const complete = MulCompleteConfig.configure(meta, a[9], addConfig);
    const overflow = MulOverflowConfig.configure(meta, lookup, [
      a[6],
      a[7],
      a[8],
    ]);
    const config = new MulConfig(
      meta.selector(),
      addConfig,
      hi,
      lo,
      complete,
      overflow,
    );
    meta.createGate("LSB check", (m) => {
      const q = m.querySelector(config.qMulLsb);
      const z1 = m.queryAdvice(complete.zComplete, 0);
      const z0 = m.queryAdvice(complete.zComplete, 1);
      const xP = m.queryAdvice(addConfig.xP, 0);
      const yP = m.queryAdvice(addConfig.yP, 0);
      const baseX = m.queryAdvice(addConfig.xP, 1);
      const baseY = m.queryAdvice(addConfig.yP, 1);
      const lsb = sub(z0, scale(z1, 2n));
      const bool = boolCheck(lsb);
      const lsbX = ternary(lsb, xP, sub(xP, baseX));
      const lsbY = ternary(lsb, yP, add(yP, baseY));
      return [mul(q, bool), mul(q, lsbX), mul(q, lsbY)];
    });
    return config;
  }

  /** `[alpha]base`, with the overflow check of `alpha`. */
  assign(
    layouter: Layouter,
    alpha: AssignedCell,
    base: NonIdentityEccPoint,
  ): EccPoint {
    const { result, zs } = layouter.assignRegion((region) => {
      const basePoint = new EccPoint(base.x, base.y);
      const bits = decompose(alpha.value);
      const bitsHi = bits.slice(0, INCOMPLETE_HI_LEN);
      const bitsLo = bits.slice(INCOMPLETE_HI_LEN, INCOMPLETE_LEN);
      const lsb = bits[NUM_BITS - 1];

      const acc = this.addConfig.assignRegion(basePoint, basePoint, 0, region);
      const offset = 1;
      const zInit = region.assignAdviceFromConstant(this.hi.z, offset, 0n);
      const hi = this.hi.doubleAndAdd(region, offset, base, bitsHi, {
        x: acc.x,
        y: acc.y,
        z: zInit,
      });
      const lo = this.lo.doubleAndAdd(region, offset, base, bitsLo, {
        x: hi.x,
        y: hi.y,
        z: hi.zs[hi.zs.length - 1],
      });
      const completeOffset = offset + INCOMPLETE_LO_LEN + 2;
      const done = this.complete.assignRegion(
        region,
        completeOffset,
        bits.slice(INCOMPLETE_LEN, INCOMPLETE_LEN + NUM_COMPLETE_BITS),
        basePoint,
        lo.x,
        lo.y,
        lo.zs[lo.zs.length - 1],
      );
      const lsbOffset = completeOffset + NUM_COMPLETE_BITS * 2;
      const z1 = done.zs[done.zs.length - 1];
      const { point, z0 } = this.processLsb(
        region,
        lsbOffset,
        base,
        done.acc,
        z1,
        lsb,
      );
      const all = [zInit, ...hi.zs, ...lo.zs, ...done.zs, z0];
      if (all.length !== NUM_BITS + 1) throw new Error("running sum length");
      return { result: point, zs: all.reverse() };
    });
    this.overflow.overflowCheck(layouter, alpha, zs);
    return result;
  }

  private processLsb(
    region: Region,
    offset: number,
    base: NonIdentityEccPoint,
    acc: EccPoint,
    z1: AssignedCell,
    lsb: boolean | undefined,
  ): { point: EccPoint; z0: AssignedCell } {
    region.enableSelector(this.qMulLsb, offset);
    const kv = lsb === undefined ? undefined : lsb ? 1n : 0n;
    const z0Val = vzip([z1.value, kv], (z, b) => Fp.add(Fp.mul(z, 2n), b));
    const z0 = region.assignAdvice(
      this.complete.zComplete,
      offset + 1,
      () => z0Val,
    );
    base.x.copyAdvice(region, this.addConfig.xP, offset + 1);
    base.y.copyAdvice(region, this.addConfig.yP, offset + 1);
    const x = lsb === undefined ? undefined : lsb ? 0n : base.x.value;
    const y =
      lsb === undefined
        ? undefined
        : lsb
          ? 0n
          : base.y.value === undefined
            ? undefined
            : Fp.neg(base.y.value);
    const xCell = region.assignAdvice(this.addConfig.xP, offset, () => x);
    const yCell = region.assignAdvice(this.addConfig.yP, offset, () => y);
    const point = this.addConfig.assignRegion(
      new EccPoint(xCell, yCell),
      acc,
      offset,
      region,
    );
    return { point, z0 };
  }
}
