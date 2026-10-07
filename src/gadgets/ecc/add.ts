/**
 * Complete point addition, a port of halo2_gadgets 0.5 `ecc::chip::add`.
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
import { vzip, type Region, type Value } from "../../halo2/layouter.js";
import { EccPoint } from "./point.js";

/** `inv0`: the inverse, or zero for zero (halo2 `Assigned::invert`). */
export const inv0 = (v: bigint): bigint => (v === 0n ? 0n : Fp.inv(v));

export class AddConfig {
  private constructor(
    readonly q: Selector,
    readonly lambda: Column<"Advice">,
    readonly xP: Column<"Advice">,
    readonly yP: Column<"Advice">,
    readonly xQr: Column<"Advice">,
    readonly yQr: Column<"Advice">,
    readonly alpha: Column<"Advice">,
    readonly beta: Column<"Advice">,
    readonly gamma: Column<"Advice">,
    readonly delta: Column<"Advice">,
  ) {}

  static configure(
    meta: ConstraintSystem,
    xP: Column<"Advice">,
    yP: Column<"Advice">,
    xQr: Column<"Advice">,
    yQr: Column<"Advice">,
    lambda: Column<"Advice">,
    alpha: Column<"Advice">,
    beta: Column<"Advice">,
    gamma: Column<"Advice">,
    delta: Column<"Advice">,
  ): AddConfig {
    for (const c of [xP, yP, xQr, yQr]) meta.enableEquality(c);
    const config = new AddConfig(
      meta.selector(),
      lambda,
      xP,
      yP,
      xQr,
      yQr,
      alpha,
      beta,
      gamma,
      delta,
    );
    meta.createGate("complete addition", (m) => {
      const q = m.querySelector(config.q);
      const xp = m.queryAdvice(xP, 0);
      const yp = m.queryAdvice(yP, 0);
      const xq = m.queryAdvice(xQr, 0);
      const yq = m.queryAdvice(yQr, 0);
      const xr = m.queryAdvice(xQr, 1);
      const yr = m.queryAdvice(yQr, 1);
      const lam = m.queryAdvice(lambda, 0);
      const al = m.queryAdvice(alpha, 0);
      const be = m.queryAdvice(beta, 0);
      const ga = m.queryAdvice(gamma, 0);
      const de = m.queryAdvice(delta, 0);

      const xqMinusXp = sub(xq, xp);
      const xpMinusXr = sub(xp, xr);
      const yqPlusYp = add(yq, yp);
      const ifAlpha = mul(xqMinusXp, al);
      const ifBeta = mul(xp, be);
      const ifGamma = mul(xq, ga);
      const ifDelta = mul(yqPlusYp, de);
      const one = constant(1);
      const two = constant(2);
      const three = constant(3);

      const poly1 = mul(xqMinusXp, sub(mul(xqMinusXp, lam), sub(yq, yp)));
      const poly2 = mul(
        sub(one, ifAlpha),
        sub(mul(mul(two, yp), lam), mul(three, mul(xp, xp))),
      );
      const nonexceptionalXr = sub(sub(sub(mul(lam, lam), xp), xq), xr);
      const nonexceptionalYr = sub(sub(mul(lam, xpMinusXr), yp), yr);
      const poly3a = mul(mul(mul(xp, xq), xqMinusXp), nonexceptionalXr);
      const poly3b = mul(mul(mul(xp, xq), xqMinusXp), nonexceptionalYr);
      const poly3c = mul(mul(mul(xp, xq), yqPlusYp), nonexceptionalXr);
      const poly3d = mul(mul(mul(xp, xq), yqPlusYp), nonexceptionalYr);
      const poly4a = mul(sub(one, ifBeta), sub(xr, xq));
      const poly4b = mul(sub(one, ifBeta), sub(yr, yq));
      const poly5a = mul(sub(one, ifGamma), sub(xr, xp));
      const poly5b = mul(sub(one, ifGamma), sub(yr, yp));
      const poly6a = mul(sub(sub(one, ifAlpha), ifDelta), xr);
      const poly6b = mul(sub(sub(one, ifAlpha), ifDelta), yr);
      return [
        poly1,
        poly2,
        poly3a,
        poly3b,
        poly3c,
        poly3d,
        poly4a,
        poly4b,
        poly5a,
        poly5b,
        poly6a,
        poly6b,
      ].map((p) => mul(q, p));
    });
    return config;
  }

  /** `P + Q` in rows `offset` and `offset + 1`. */
  assignRegion(
    p: EccPoint,
    q: EccPoint,
    offset: number,
    region: Region,
  ): EccPoint {
    region.enableSelector(this.q, offset);
    p.x.copyAdvice(region, this.xP, offset);
    p.y.copyAdvice(region, this.yP, offset);
    q.x.copyAdvice(region, this.xQr, offset);
    q.y.copyAdvice(region, this.yQr, offset);
    const xp = p.x.value;
    const yp = p.y.value;
    const xq = q.x.value;
    const yq = q.y.value;

    const alpha = vzip([xq, xp], (a, b) => inv0(Fp.sub(a, b)));
    region.assignAdvice(this.alpha, offset, () => alpha);
    const beta = vzip([xp], (a) => inv0(a));
    region.assignAdvice(this.beta, offset, () => beta);
    const gamma = vzip([xq], (a) => inv0(a));
    region.assignAdvice(this.gamma, offset, () => gamma);
    const delta = vzip([xp, xq, yp, yq], (xp_, xq_, yp_, yq_) =>
      xq_ === xp_ ? inv0(Fp.add(yq_, yp_)) : 0n,
    );
    region.assignAdvice(this.delta, offset, () => delta);
    const lambda = vzip([xp, yp, xq, yq, alpha], (xp_, yp_, xq_, yq_, al) => {
      if (xq_ !== xp_) return Fp.mul(Fp.sub(yq_, yp_), al);
      if (yp_ !== 0n)
        return Fp.mul(
          Fp.mul(Fp.square(xp_), 3n),
          Fp.mul(inv0(yp_), Fp.inv(2n)),
        );
      return 0n;
    });
    region.assignAdvice(this.lambda, offset, () => lambda);

    let xr: Value;
    let yr: Value;
    if ([xp, yp, xq, yq, lambda].some((v) => v === undefined)) {
      xr = undefined;
      yr = undefined;
    } else {
      const [a, b, c, d, lam] = [xp, yp, xq, yq, lambda] as bigint[];
      if (a === 0n) [xr, yr] = [c, d];
      else if (c === 0n) [xr, yr] = [a, b];
      else if (c === a && d === Fp.neg(b)) [xr, yr] = [0n, 0n];
      else {
        const x = Fp.sub(Fp.sub(Fp.square(lam), a), c);
        [xr, yr] = [x, Fp.sub(Fp.mul(lam, Fp.sub(a, x)), b)];
      }
    }
    const xCell = region.assignAdvice(this.xQr, offset + 1, () => xr);
    const yCell = region.assignAdvice(this.yQr, offset + 1, () => yr);
    return new EccPoint(xCell, yCell);
  }
}
