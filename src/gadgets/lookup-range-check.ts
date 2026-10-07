/**
 * K-bit lookup range check, a port of halo2_gadgets 0.5
 * `utilities::lookup_range_check::LookupRangeCheckConfig`: a running-sum
 * decomposition into K-bit words looked up in a table of [0, 2^K), and the
 * short check of a value below K bits by a shifted lookup.
 */
import { Fp } from "../field.js";
import {
  add,
  constant,
  mul,
  scale,
  sub,
  type Column,
  type Selector,
} from "../halo2/expression.js";
import type {
  ConstraintSystem,
  TableColumn,
} from "../halo2/constraint-system.js";
import {
  vmap,
  vzip,
  type AssignedCell,
  type Layouter,
  type Region,
} from "../halo2/layouter.js";

export class LookupRangeCheckConfig {
  private constructor(
    readonly qLookup: Selector,
    readonly qRunning: Selector,
    readonly qBitshift: Selector,
    readonly runningSum: Column<"Advice">,
    readonly tableIdx: TableColumn,
    readonly k: number,
  ) {}

  static configure(
    meta: ConstraintSystem,
    runningSum: Column<"Advice">,
    tableIdx: TableColumn,
    k: number,
  ): LookupRangeCheckConfig {
    meta.enableEquality(runningSum);
    const qLookup = meta.complexSelector();
    const qRunning = meta.complexSelector();
    const qBitshift = meta.selector();
    const config = new LookupRangeCheckConfig(
      qLookup,
      qRunning,
      qBitshift,
      runningSum,
      tableIdx,
      k,
    );
    const twoPowK = 1n << BigInt(k);

    meta.lookup((m) => {
      const qL = m.querySelector(qLookup);
      const qR = m.querySelector(qRunning);
      const zCur = m.queryAdvice(runningSum, 0);
      const one = constant(1);
      const runningSumLookup = mul(
        qR,
        sub(zCur, scale(m.queryAdvice(runningSum, 1), twoPowK)),
      );
      const shortLookup = mul(sub(one, qR), zCur);
      return [[mul(qL, add(runningSumLookup, shortLookup)), tableIdx]];
    });

    meta.createGate("Short lookup bitshift", (m) => {
      const q = m.querySelector(qBitshift);
      const word = m.queryAdvice(runningSum, -1);
      const shifted = m.queryAdvice(runningSum, 0);
      const invTwoPowS = m.queryAdvice(runningSum, 1);
      return [mul(q, sub(mul(scale(word, twoPowK), invTwoPowS), shifted))];
    });
    return config;
  }

  /** Copy `element` in and decompose it into `numWords` K-bit words. */
  copyCheck(
    layouter: Layouter,
    element: AssignedCell,
    numWords: number,
    strict: boolean,
  ): AssignedCell[] {
    return layouter.assignRegion((region) => {
      const z0 = element.copyAdvice(region, this.runningSum, 0);
      return this.rangeCheck(region, z0, numWords, strict);
    });
  }

  /** The running sum `z_0 = element, z_{i+1} = (z_i - a_i) / 2^K`. */
  rangeCheck(
    region: Region,
    element: AssignedCell,
    numWords: number,
    strict: boolean,
  ): AssignedCell[] {
    const k = BigInt(this.k);
    const mask = (1n << k) - 1n;
    const words = Array.from({ length: numWords }, (_, i) =>
      vmap(element.value, (v) => (v >> (BigInt(i) * k)) & mask),
    );
    const zs = [element];
    let z = element;
    const invTwoPowK = Fp.inv(1n << k);
    words.forEach((word, idx) => {
      region.enableSelector(this.qLookup, idx);
      region.enableSelector(this.qRunning, idx);
      const zVal = vzip([z.value, word], (zv, w) =>
        Fp.mul(Fp.sub(zv, w), invTwoPowK),
      );
      z = region.assignAdvice(this.runningSum, idx + 1, () => zVal);
      zs.push(z);
    });
    if (strict) region.constrainConstant(zs[zs.length - 1].cell, 0n);
    return zs;
  }

  /** Copy `element` in and check it is below `numBits` bits (`numBits < K`). */
  copyShortCheck(
    layouter: Layouter,
    element: AssignedCell,
    numBits: number,
  ): void {
    if (numBits >= this.k)
      throw new Error("short check needs fewer bits than K");
    layouter.assignRegion((region) => {
      const e = element.copyAdvice(region, this.runningSum, 0);
      this.shortRangeCheck(region, e, numBits);
    });
  }

  shortRangeCheck(
    region: Region,
    element: AssignedCell,
    numBits: number,
  ): void {
    region.enableSelector(this.qLookup, 0);
    region.enableSelector(this.qLookup, 1);
    region.enableSelector(this.qBitshift, 1);
    const shift = 1n << BigInt(this.k - numBits);
    const shifted = vmap(element.value, (v) => Fp.mul(v, shift));
    region.assignAdvice(this.runningSum, 1, () => shifted);
    region.assignAdviceFromConstant(
      this.runningSum,
      2,
      Fp.inv(1n << BigInt(numBits)),
    );
  }
}
