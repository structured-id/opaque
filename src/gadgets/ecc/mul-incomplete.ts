/**
 * Double-and-add over incomplete addition for the `hi` and `lo` halves of a
 * variable-base scalar multiplication, a port of halo2_gadgets 0.5
 * `ecc::chip::mul::incomplete`.
 */
import { Fp } from "../../field.js";
import {
  add,
  constant,
  mul,
  scale,
  sub,
  type Column,
  type Expression,
  type Selector,
} from "../../halo2/expression.js";
import type {
  ConstraintSystem,
  VirtualCells,
} from "../../halo2/constraint-system.js";
import {
  vzip,
  type AssignedCell,
  type Region,
  type Value,
} from "../../halo2/layouter.js";
import { boolCheck } from "../utilities.js";
import { inv0 } from "./add.js";
import type { NonIdentityEccPoint } from "./point.js";

const TWO_INV = Fp.inv(2n);

/** The columns of one double-and-add row. */
export interface DoubleAndAdd {
  xA: Column<"Advice">;
  xP: Column<"Advice">;
  lambda1: Column<"Advice">;
  lambda2: Column<"Advice">;
}

/** `x_r = λ1² - x_a - x_p`. */
function xR(m: VirtualCells, d: DoubleAndAdd, rotation: number): Expression {
  const xA = m.queryAdvice(d.xA, rotation);
  const xP = m.queryAdvice(d.xP, rotation);
  const l1 = m.queryAdvice(d.lambda1, rotation);
  return sub(sub(mul(l1, l1), xA), xP);
}

/** `Y_A = (λ1 + λ2)·(x_a - x_r)`. */
function yA(m: VirtualCells, d: DoubleAndAdd, rotation: number): Expression {
  const xA = m.queryAdvice(d.xA, rotation);
  const l1 = m.queryAdvice(d.lambda1, rotation);
  const l2 = m.queryAdvice(d.lambda2, rotation);
  return mul(add(l1, l2), sub(xA, xR(m, d, rotation)));
}

export class MulIncompleteConfig {
  private constructor(
    readonly qMul1: Selector,
    readonly qMul2: Selector,
    readonly qMul3: Selector,
    readonly z: Column<"Advice">,
    readonly cols: DoubleAndAdd,
    readonly yP: Column<"Advice">,
    readonly numBits: number,
  ) {}

  static configure(
    meta: ConstraintSystem,
    numBits: number,
    z: Column<"Advice">,
    xA: Column<"Advice">,
    xP: Column<"Advice">,
    yP: Column<"Advice">,
    lambda1: Column<"Advice">,
    lambda2: Column<"Advice">,
  ): MulIncompleteConfig {
    meta.enableEquality(z);
    meta.enableEquality(lambda1);
    const d: DoubleAndAdd = { xA, xP, lambda1, lambda2 };
    const config = new MulIncompleteConfig(
      meta.selector(),
      meta.selector(),
      meta.selector(),
      z,
      d,
      yP,
      numBits,
    );

    const ya = (m: VirtualCells, rotation: number) =>
      scale(yA(m, d, rotation), TWO_INV);

    const forLoop = (m: VirtualCells, yANext: Expression): Expression[] => {
      const one = constant(1);
      const zCur = m.queryAdvice(z, 0);
      const zPrev = m.queryAdvice(z, -1);
      const xACur = m.queryAdvice(xA, 0);
      const xANext = m.queryAdvice(xA, 1);
      const xPCur = m.queryAdvice(xP, 0);
      const yPCur = m.queryAdvice(yP, 0);
      const l1Cur = m.queryAdvice(lambda1, 0);
      const l2Cur = m.queryAdvice(lambda2, 0);
      const yACur = ya(m, 0);
      const k = sub(zCur, scale(zPrev, 2n));
      const bool = boolCheck(k);
      const gradient1 = add(
        sub(mul(l1Cur, sub(xACur, xPCur)), yACur),
        mul(sub(scale(k, 2n), one), yPCur),
      );
      const secant = sub(
        sub(sub(mul(l2Cur, l2Cur), xANext), xR(m, d, 0)),
        xACur,
      );
      const gradient2 = sub(sub(mul(l2Cur, sub(xACur, xANext)), yACur), yANext);
      return [bool, gradient1, secant, gradient2];
    };

    meta.createGate("q_mul_1 == 1 checks", (m) => {
      const q = m.querySelector(config.qMul1);
      const yANext = ya(m, 1);
      const yAWitnessed = m.queryAdvice(lambda1, 0);
      return [mul(q, sub(yAWitnessed, yANext))];
    });
    meta.createGate("q_mul_2 == 1 checks", (m) => {
      const q = m.querySelector(config.qMul2);
      const yANext = ya(m, 1);
      const xPCur = m.queryAdvice(xP, 0);
      const xPNext = m.queryAdvice(xP, 1);
      const yPCur = m.queryAdvice(yP, 0);
      const yPNext = m.queryAdvice(yP, 1);
      const xPCheck = sub(xPCur, xPNext);
      const yPCheck = sub(yPCur, yPNext);
      return [xPCheck, yPCheck, ...forLoop(m, yANext)].map((p) => mul(q, p));
    });
    meta.createGate("q_mul_3 == 1 checks", (m) => {
      const q = m.querySelector(config.qMul3);
      const yAFinal = m.queryAdvice(lambda1, 1);
      return forLoop(m, yAFinal).map((p) => mul(q, p));
    });
    return config;
  }

  /**
   * Double-and-add over `bits` (big-endian) from the accumulator `acc`,
   * anchoring the loop's base to `base` in the first loop row. Returns the
   * accumulator cells and the running sums.
   */
  doubleAndAdd(
    region: Region,
    offset: number,
    base: NonIdentityEccPoint,
    bits: (boolean | undefined)[],
    acc: { x: AssignedCell; y: AssignedCell; z: AssignedCell },
  ): { x: AssignedCell; y: AssignedCell; zs: AssignedCell[] } {
    if (bits.length !== this.numBits) throw new Error("wrong bit count");
    const xP = base.x.value;
    const yP = base.y.value;
    const xA0 = acc.x.value;
    const yA0 = acc.y.value;
    if ([xP, yP, xA0, yA0].every((v) => v !== undefined)) {
      if ((xP === 0n && yP === 0n) || (xA0 === 0n && yA0 === 0n) || xP === xA0)
        throw new Error("incomplete addition: exceptional case");
    }

    region.enableSelector(this.qMul1, offset);
    for (let i = 0; i < this.numBits - 1; i++)
      region.enableSelector(this.qMul2, offset + 1 + i);
    region.enableSelector(this.qMul3, offset + this.numBits);

    let z = acc.z.copyAdvice(region, this.z, offset);
    let xA = acc.x.copyAdvice(region, this.cols.xA, offset + 1);
    let yA: Value = acc.y.copyAdvice(region, this.cols.lambda1, offset).value;
    const row0 = offset + 1;
    const zs: AssignedCell[] = [];

    bits.forEach((k, row) => {
      const zVal = vzip(
        [z.value, k === undefined ? undefined : k ? 1n : 0n],
        (zv, kv) => Fp.add(Fp.mul(2n, zv), kv),
      );
      z = region.assignAdvice(this.z, row + row0, () => zVal);
      zs.push(z);

      if (row === 0) {
        base.x.copyAdvice(region, this.cols.xP, row + row0);
        base.y.copyAdvice(region, this.yP, row + row0);
      } else {
        region.assignAdvice(this.cols.xP, row + row0, () => xP);
        region.assignAdvice(this.yP, row + row0, () => yP);
      }

      const yPk =
        yP === undefined || k === undefined ? undefined : k ? yP : Fp.neg(yP);
      const lambda1 = vzip([yA, yPk, xA.value, xP], (ya_, yp_, xa_, xp_) =>
        Fp.mul(Fp.sub(ya_, yp_), inv0(Fp.sub(xa_, xp_))),
      );
      region.assignAdvice(this.cols.lambda1, row + row0, () => lambda1);
      const xr = vzip([lambda1, xA.value, xP], (l1, xa_, xp_) =>
        Fp.sub(Fp.sub(Fp.square(l1), xa_), xp_),
      );
      const lambda2 = vzip([lambda1, yA, xA.value, xr], (l1, ya_, xa_, xr_) =>
        Fp.sub(Fp.mul(Fp.mul(ya_, 2n), inv0(Fp.sub(xa_, xr_))), l1),
      );
      region.assignAdvice(this.cols.lambda2, row + row0, () => lambda2);

      const xANew = vzip([lambda2, xA.value, xr], (l2, xa_, xr_) =>
        Fp.sub(Fp.sub(Fp.square(l2), xa_), xr_),
      );
      yA = vzip([lambda2, xA.value, xANew, yA], (l2, xa_, xn, ya_) =>
        Fp.sub(Fp.mul(l2, Fp.sub(xa_, xn)), ya_),
      );
      xA = region.assignAdvice(this.cols.xA, row + row0 + 1, () => xANew);
    });

    const yFinal = yA;
    const yCell = region.assignAdvice(
      this.cols.lambda1,
      row0 + this.numBits,
      () => yFinal,
    );
    return { x: xA, y: yCell, zs };
  }
}
