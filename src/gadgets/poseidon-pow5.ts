/**
 * Poseidon over Pallas, width 3 and rate 2 (P128Pow5T3), a port of
 * halo2_gadgets 0.5 `poseidon::pow5::Pow5Chip` and the `Hash` sponge for
 * `ConstantLength<2>`: one full round per row, two partial rounds per row.
 */
import { Fp } from "../field.js";
import { POSEIDON_MDS, POSEIDON_RC } from "../poseidon-constants.js";
import {
  add,
  mul,
  scale,
  sub,
  type Column,
  type Expression,
  type Selector,
} from "../halo2/expression.js";
import type {
  ConstraintSystem,
  VirtualCells,
} from "../halo2/constraint-system.js";
import {
  vzip,
  type AssignedCell,
  type Layouter,
  type Region,
  type Value,
} from "../halo2/layouter.js";

const WIDTH = 3;
const RATE = 2;
const HALF_FULL_ROUNDS = 4;
const HALF_PARTIAL_ROUNDS = 28;

/** Inverse of a 3×3 matrix over the field. */
function invert3(m: readonly (readonly bigint[])[]): bigint[][] {
  const [a, b, c] = m[0];
  const [d, e, f] = m[1];
  const [g, h, i] = m[2];
  const sub2 = (x: bigint, y: bigint) => Fp.sub(x, y);
  const A = sub2(Fp.mul(e, i), Fp.mul(f, h));
  const B = Fp.neg(sub2(Fp.mul(d, i), Fp.mul(f, g)));
  const C = sub2(Fp.mul(d, h), Fp.mul(e, g));
  const det = Fp.add(Fp.add(Fp.mul(a, A), Fp.mul(b, B)), Fp.mul(c, C));
  const inv = Fp.inv(det);
  const adj = [
    [
      A,
      Fp.neg(sub2(Fp.mul(b, i), Fp.mul(c, h))),
      sub2(Fp.mul(b, f), Fp.mul(c, e)),
    ],
    [
      B,
      sub2(Fp.mul(a, i), Fp.mul(c, g)),
      Fp.neg(sub2(Fp.mul(a, f), Fp.mul(c, d))),
    ],
    [
      C,
      Fp.neg(sub2(Fp.mul(a, h), Fp.mul(b, g))),
      sub2(Fp.mul(a, e), Fp.mul(b, d)),
    ],
  ];
  return adj.map((row) => row.map((v) => Fp.mul(v, inv)));
}

const M = POSEIDON_MDS;
const M_INV = invert3(POSEIDON_MDS);

const pow5 = (v: Expression): Expression => {
  const v2 = mul(v, v);
  return mul(mul(v2, v2), v);
};

const fpow5 = (v: bigint): bigint => Fp.mul(Fp.square(Fp.square(v)), v);

export class Pow5Config {
  private constructor(
    readonly state: Column<"Advice">[],
    readonly partialSbox: Column<"Advice">,
    readonly rcA: Column<"Fixed">[],
    readonly rcB: Column<"Fixed">[],
    readonly sFull: Selector,
    readonly sPartial: Selector,
    readonly sPadAndAdd: Selector,
  ) {}

  static configure(
    meta: ConstraintSystem,
    state: Column<"Advice">[],
    partialSbox: Column<"Advice">,
    rcA: Column<"Fixed">[],
    rcB: Column<"Fixed">[],
  ): Pow5Config {
    for (const c of state) meta.enableEquality(c);
    for (const c of rcB) meta.enableEquality(c);
    const sFull = meta.selector();
    const sPartial = meta.selector();
    const sPadAndAdd = meta.selector();

    meta.createGate("full round", (m) => {
      const q = m.querySelector(sFull);
      const polys: Expression[] = [];
      for (let next = 0; next < WIDTH; next++) {
        const stateNext = m.queryAdvice(state[next], 1);
        let expr: Expression | null = null;
        for (let idx = 0; idx < WIDTH; idx++) {
          const cur = m.queryAdvice(state[idx], 0);
          const rc = m.queryFixed(rcA[idx]);
          const term = scale(pow5(add(cur, rc)), M[next][idx]);
          expr = expr === null ? term : add(expr, term);
        }
        polys.push(sub(expr as Expression, stateNext));
      }
      return polys.map((p) => mul(q, p));
    });

    meta.createGate("partial rounds", (m) => {
      const cur0 = m.queryAdvice(state[0], 0);
      const mid0 = m.queryAdvice(partialSbox, 0);
      const rcA0 = m.queryFixed(rcA[0]);
      const rcB0 = m.queryFixed(rcB[0]);
      const q = m.querySelector(sPartial);
      const mid = (idx: number, v: VirtualCells): Expression => {
        let acc = scale(mid0, M[idx][0]);
        for (let c = 1; c < WIDTH; c++) {
          const cur = v.queryAdvice(state[c], 0);
          const rc = v.queryFixed(rcA[c]);
          acc = add(acc, scale(add(cur, rc), M[idx][c]));
        }
        return acc;
      };
      const next = (idx: number, v: VirtualCells): Expression => {
        let acc: Expression | null = null;
        for (let n = 0; n < WIDTH; n++) {
          const term = scale(v.queryAdvice(state[n], 1), M_INV[idx][n]);
          acc = acc === null ? term : add(acc, term);
        }
        return acc as Expression;
      };
      const linear = (idx: number, v: VirtualCells): Expression => {
        const rc = v.queryFixed(rcB[idx]);
        return sub(add(mid(idx, v), rc), next(idx, v));
      };
      const polys = [
        sub(pow5(add(cur0, rcA0)), mid0),
        sub(pow5(add(mid(0, m), rcB0)), next(0, m)),
      ];
      for (let idx = 1; idx < WIDTH; idx++) polys.push(linear(idx, m));
      return polys.map((p) => mul(q, p));
    });

    meta.createGate("pad-and-add", (m) => {
      const initialRate = m.queryAdvice(state[RATE], -1);
      const outputRate = m.queryAdvice(state[RATE], 1);
      const q = m.querySelector(sPadAndAdd);
      const polys: Expression[] = [];
      for (let idx = 0; idx < RATE; idx++) {
        const initial = m.queryAdvice(state[idx], -1);
        const input = m.queryAdvice(state[idx], 0);
        const output = m.queryAdvice(state[idx], 1);
        polys.push(sub(add(initial, input), output));
      }
      polys.push(sub(initialRate, outputRate));
      return polys.map((p) => mul(q, p));
    });

    return new Pow5Config(
      state,
      partialSbox,
      rcA,
      rcB,
      sFull,
      sPartial,
      sPadAndAdd,
    );
  }

  /** `Hash::<ConstantLength<2>>::init` then `hash([a, b])`. */
  hash2(
    layouter: Layouter,
    inputs: [AssignedCell, AssignedCell],
  ): AssignedCell {
    const initial = layouter.assignRegion((region) => [
      region.assignAdviceFromConstant(this.state[0], 0, 0n),
      region.assignAdviceFromConstant(this.state[1], 0, 0n),
      // ConstantLength<2>: capacity element L·2^64.
      region.assignAdviceFromConstant(this.state[2], 0, 2n << 64n),
    ]);
    const added = layouter.assignRegion((region) => {
      region.enableSelector(this.sPadAndAdd, 1);
      const init = initial.map((w, i) =>
        w.copyAdvice(region, this.state[i], 0),
      );
      const input = inputs.map((word, i) => {
        const v = word.value;
        const cell = region.assignAdvice(this.state[i], 1, () => v);
        region.constrainEqual(word.cell, cell.cell);
        return cell;
      });
      return init.map((w, i) => {
        const value = vzip([w.value, i < RATE ? input[i].value : 0n], (a, b) =>
          Fp.add(a, b),
        );
        return region.assignAdvice(this.state[i], 2, () => value);
      });
    });
    const out = this.permute(layouter, added);
    return out[0];
  }

  private permute(layouter: Layouter, initial: AssignedCell[]): AssignedCell[] {
    return layouter.assignRegion((region) => {
      let state = initial.map((w, i) => w.copyAdvice(region, this.state[i], 0));
      for (let r = 0; r < HALF_FULL_ROUNDS; r++)
        state = this.fullRound(region, state, r, r);
      for (let r = 0; r < HALF_PARTIAL_ROUNDS; r++)
        state = this.partialRound(
          region,
          state,
          HALF_FULL_ROUNDS + 2 * r,
          HALF_FULL_ROUNDS + r,
        );
      for (let r = 0; r < HALF_FULL_ROUNDS; r++)
        state = this.fullRound(
          region,
          state,
          HALF_FULL_ROUNDS + 2 * HALF_PARTIAL_ROUNDS + r,
          HALF_FULL_ROUNDS + HALF_PARTIAL_ROUNDS + r,
        );
      return state;
    });
  }

  private loadRoundConstants(
    region: Region,
    round: number,
    offset: number,
  ): void {
    for (let i = 0; i < WIDTH; i++)
      region.assignFixed(this.rcA[i], offset, POSEIDON_RC[round][i]);
  }

  private nextState(
    region: Region,
    offset: number,
    next: Value[],
  ): AssignedCell[] {
    return next.map((v, i) =>
      region.assignAdvice(this.state[i], offset + 1, () => v),
    );
  }

  private fullRound(
    region: Region,
    state: AssignedCell[],
    round: number,
    offset: number,
  ): AssignedCell[] {
    region.enableSelector(this.sFull, offset);
    this.loadRoundConstants(region, round, offset);
    const values = state.map((w) => w.value);
    let next: Value[];
    if (values.some((v) => v === undefined))
      next = [undefined, undefined, undefined];
    else {
      const r = (values as bigint[]).map((v, i) =>
        fpow5(Fp.add(v, POSEIDON_RC[round][i])),
      );
      next = M.map((row) =>
        row.reduce((acc, mij, j) => Fp.add(acc, Fp.mul(mij, r[j])), 0n),
      );
    }
    return this.nextState(region, offset, next);
  }

  private partialRound(
    region: Region,
    state: AssignedCell[],
    round: number,
    offset: number,
  ): AssignedCell[] {
    region.enableSelector(this.sPartial, offset);
    this.loadRoundConstants(region, round, offset);
    const values = state.map((w) => w.value);
    const known = values.every((v) => v !== undefined);
    const p = values as bigint[];
    const r = known
      ? [
          fpow5(Fp.add(p[0], POSEIDON_RC[round][0])),
          Fp.add(p[1], POSEIDON_RC[round][1]),
          Fp.add(p[2], POSEIDON_RC[round][2]),
        ]
      : null;
    region.assignAdvice(this.partialSbox, offset, () => (r ? r[0] : undefined));
    const pMid = r
      ? M.map((row) =>
          row.reduce((acc, mij, j) => Fp.add(acc, Fp.mul(mij, r[j])), 0n),
        )
      : null;
    for (let i = 0; i < WIDTH; i++)
      region.assignFixed(this.rcB[i], offset, POSEIDON_RC[round + 1][i]);
    const rMid = pMid
      ? [
          fpow5(Fp.add(pMid[0], POSEIDON_RC[round + 1][0])),
          Fp.add(pMid[1], POSEIDON_RC[round + 1][1]),
          Fp.add(pMid[2], POSEIDON_RC[round + 1][2]),
        ]
      : null;
    const next: Value[] = rMid
      ? M.map((row) =>
          row.reduce((acc, mij, j) => Fp.add(acc, Fp.mul(mij, rMid[j])), 0n),
        )
      : [undefined, undefined, undefined];
    return this.nextState(region, offset, next);
  }
}
