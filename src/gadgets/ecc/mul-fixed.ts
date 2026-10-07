/**
 * Fixed-base scalar multiplication configs of halo2_gadgets 0.5
 * `ecc::chip::mul_fixed` (shared config, full-width, short, base-field
 * element). This circuit never multiplies by a fixed base, so only the
 * columns and gates are ported: they are part of the constraint system.
 */
import { FP_MODULUS } from "../../field.js";
import {
  add,
  constant,
  mul,
  scale,
  sub,
  type Column,
  type Expression,
} from "../../halo2/expression.js";
import type {
  ConstraintSystem,
  VirtualCells,
} from "../../halo2/constraint-system.js";
import { boolCheck, rangeCheck } from "../utilities.js";
import type { AddConfig } from "./add.js";
import type { AddIncompleteConfig } from "./add-incomplete.js";

/** Window width of fixed-base multiplication, and `H = 2^3` points per window. */
const WINDOW_BITS = 3;
const H = 1 << WINDOW_BITS;

/** `t_p`: the Pallas base field modulus is `2^254 + t_p`. */
const T_P = FP_MODULUS - (1n << 254n);

export class MulFixedConfig {
  private constructor(
    readonly lagrangeCoeffs: Column<"Fixed">[],
    readonly fixedZ: Column<"Fixed">,
    readonly window: Column<"Advice">,
    readonly u: Column<"Advice">,
    readonly addConfig: AddConfig,
  ) {}

  static configure(
    meta: ConstraintSystem,
    lagrangeCoeffs: Column<"Fixed">[],
    window: Column<"Advice">,
    u: Column<"Advice">,
    addConfig: AddConfig,
    _addIncomplete: AddIncompleteConfig,
  ): MulFixedConfig {
    meta.enableEquality(window);
    meta.enableEquality(u);
    const qRunningSum = meta.selector();
    // RunningSumConfig::configure (3-bit windows)
    meta.enableEquality(window);
    meta.createGate("range check", (m) => {
      const q = m.querySelector(qRunningSum);
      const zCur = m.queryAdvice(window, 0);
      const zNext = m.queryAdvice(window, 1);
      const word = sub(zCur, scale(zNext, BigInt(H)));
      return [mul(q, rangeCheck(word, H))];
    });
    const config = new MulFixedConfig(
      lagrangeCoeffs,
      meta.fixedColumn(),
      window,
      u,
      addConfig,
    );
    meta.createGate("Running sum coordinates check", (m) => {
      const q = m.querySelector(qRunningSum);
      const zCur = m.queryAdvice(window, 0);
      const zNext = m.queryAdvice(window, 1);
      const word = sub(zCur, scale(zNext, BigInt(H)));
      return config.coordsCheck(m, word).map((p) => mul(q, p));
    });
    return config;
  }

  coordsCheck(m: VirtualCells, window: Expression): Expression[] {
    const yP = m.queryAdvice(this.addConfig.yP, 0);
    const xP = m.queryAdvice(this.addConfig.xP, 0);
    const z = m.queryFixed(this.fixedZ);
    const u = m.queryAdvice(this.u, 0);
    const windowPow: Expression[] = [];
    for (let pow = 0; pow < H; pow++) {
      let acc = constant(1);
      for (let i = 0; i < pow; i++) acc = mul(acc, window);
      windowPow.push(acc);
    }
    let interpolatedX = constant(0);
    for (let k = 0; k < H; k++)
      interpolatedX = add(
        interpolatedX,
        mul(windowPow[k], m.queryFixed(this.lagrangeCoeffs[k])),
      );
    const xCheck = sub(interpolatedX, xP);
    const yCheck = sub(sub(mul(u, u), yP), z);
    const onCurve = sub(sub(mul(yP, yP), mul(mul(xP, xP), xP)), constant(5));
    return [xCheck, yCheck, onCurve];
  }
}

export function configureMulFixedFull(
  meta: ConstraintSystem,
  sup: MulFixedConfig,
): void {
  const q = meta.selector();
  meta.createGate("Full-width fixed-base scalar mul", (m) => {
    const qe = m.querySelector(q);
    const window = m.queryAdvice(sup.window, 0);
    return [...sup.coordsCheck(m, window), rangeCheck(window, H)].map((p) =>
      mul(qe, p),
    );
  });
}

export function configureMulFixedShort(
  meta: ConstraintSystem,
  sup: MulFixedConfig,
): void {
  const q = meta.selector();
  meta.createGate("Short fixed-base mul gate", (m) => {
    const qe = m.querySelector(q);
    const yP = m.queryAdvice(sup.addConfig.yP, 0);
    const yA = m.queryAdvice(sup.addConfig.yQr, 0);
    const lastWindow = m.queryAdvice(sup.u, 0);
    const sign = m.queryAdvice(sup.window, 0);
    const one = constant(1);
    const lastWindowCheck = boolCheck(lastWindow);
    const signCheck = sub(mul(sign, sign), one);
    const yCheck = mul(sub(yP, yA), add(yP, yA));
    const negationCheck = sub(mul(sign, yP), yA);
    return [lastWindowCheck, signCheck, yCheck, negationCheck].map((p) =>
      mul(qe, p),
    );
  });
}

export function configureMulFixedBaseField(
  meta: ConstraintSystem,
  canon: Column<"Advice">[],
): void {
  for (const c of canon) meta.enableEquality(c);
  const q = meta.selector();
  meta.createGate("Canonicity checks", (m) => {
    const qe = m.querySelector(q);
    const alpha = m.queryAdvice(canon[0], -1);
    const z84 = m.queryAdvice(canon[2], -1);
    const alpha0 = sub(alpha, scale(z84, 1n << 252n));
    const alpha1 = m.queryAdvice(canon[1], 0);
    const alpha2 = m.queryAdvice(canon[2], 0);
    const alpha0Prime = m.queryAdvice(canon[0], 0);
    const z13 = m.queryAdvice(canon[0], 1);
    const z44 = m.queryAdvice(canon[1], 1);
    const z43 = m.queryAdvice(canon[2], 1);

    const alpha1Range = rangeCheck(alpha1, 1 << 2);
    const alpha2Range = boolCheck(alpha2);
    const z84Check = sub(z84, add(alpha1, scale(alpha2, 4n)));
    const alpha0PrimeCheck = sub(
      alpha0Prime,
      sub(add(alpha0, constant(1n << 130n)), constant(T_P)),
    );
    const alpha0Hi120 = sub(z44, mul(z84, constant(1n << 120n)));
    const a43 = sub(z43, scale(z44, BigInt(H)));
    return [
      mul(alpha2, alpha1),
      mul(alpha2, alpha0Hi120),
      mul(alpha2, boolCheck(a43)),
      mul(alpha2, z13),
      alpha1Range,
      alpha2Range,
      z84Check,
      alpha0PrimeCheck,
    ].map((p) => mul(qe, p));
  });
}
