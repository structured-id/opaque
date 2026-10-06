/**
 * The ZKPP circuit, a port of `sid_pake_core::circuit::ZkppCircuit`: Gadget
 * A (policy), Gadget C (hash-to-curve and the OPAQUE element M = blind·H_p),
 * the byte packing that binds A to C, Gadget D (breach Bloom
 * non-membership) and Gadget H (history tags). `configure` and `synthesize`
 * follow the reference call for call: column, selector and query indices and
 * the region order are what the keys and the proof depend on.
 */
import { Field as NobleField } from "@noble/curves/abstract/modular.js";
import { Fp, FP_MODULUS } from "../field.js";
import { Pallas, type Point } from "../curve.js";
import {
  add,
  constant,
  mul,
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
  type Value,
} from "../halo2/layouter.js";
import { LookupRangeCheckConfig } from "../gadgets/lookup-range-check.js";
import { EccChip, EccConfig } from "../gadgets/ecc/chip.js";
import { Pow5Config } from "../gadgets/poseidon-pow5.js";
import { hashToCurveOutside } from "../hash-to-curve.js";
import { canonicalPoint } from "../history.js";

const NFp = NobleField(FP_MODULUS);

export const MAX_PASSWORD_LEN = 128;
const BYTES_PER_FE = 31;
const HTC_TRY_BITS = 8;
const TRIES = 1 << HTC_TRY_BITS;
const HALF_WORDS = 25;
const HALF_TOP_BITS = 3;
const HASH_BITS = 255;

/** Breach Bloom filter parameters of the circuit: m = 2^8 bits, k = 3 slices. */
export const BREACH_PARAMS = { indexBits: 8, k: 3 } as const;
const BLOOM_M = 1 << BREACH_PARAMS.indexBits;

/** Password policy minimums: fixed columns of the keys. */
export interface PolicyParams {
  minLength: number;
  minUpper: number;
  minLower: number;
  minDigit: number;
  minSymbol: number;
}

/** The CE default policy (`sid_crypto::types::CE_DEFAULT_POLICY`). */
export const CE_DEFAULT_POLICY: PolicyParams = {
  minLength: 8,
  minUpper: 1,
  minLower: 1,
  minDigit: 1,
  minSymbol: 0,
};

/** What a key is built for: the policy and the number of comparison domains. */
export interface CircuitShape {
  policy: PolicyParams;
  historyDomains: number;
}

/** `M (2) + d (1) + c_j (D) + B (2) + (Z_j (2) + t_j (1))·D`. */
export const instanceCount = (domains: number): number => 5 + 4 * domains;

/** The fixed non-square of Gadget H: the base field's multiplicative generator. */
export const NON_SQUARE = 5n;

/** The witness of one proof; absent at key generation. */
export interface ZkppWitness {
  /** The password zero-padded to MAX_PASSWORD_LEN. */
  password: Uint8Array;
  passwordLen: number;
  /** The OPRF blind as a base-field element. */
  blind: bigint;
  /** Owner domain d and comparison domains c_j. */
  d: bigint;
  domains: bigint[];
  /** Gadget H witness. */
  history: HistoryTagWitness;
  /** The breach filter bits (m of them). */
  breachBits: number[];
}

export interface HistoryTagWitness {
  h: NonNullable<Point>;
  offset: number;
  /** Non-square witnesses for the offsets below `offset`. */
  w: bigint[];
  r: bigint;
  /** N_j = k_j·H per comparison domain. */
  n: NonNullable<Point>[];
}

/** The honest Gadget H witness for input `u`, blind `r` and the answers `Z_j`. */
export function historyWitness(
  u: bigint,
  r: bigint,
  z: NonNullable<Point>[],
): HistoryTagWitness {
  const { point, offset } = canonicalPoint(u);
  const w: bigint[] = [];
  for (let i = 0n; i < offset; i++) {
    const x = Fp.add(u, i);
    // g·(x³ + 5) is a square exactly when x³ + 5 is not.
    w.push(NFp.sqrt(Fp.mul(NON_SQUARE, Fp.add(Fp.mul(Fp.square(x), x), 5n))));
  }
  const inv = invScalar(r);
  const n = z.map((zj) => {
    const p = Pallas.scalarMul(inv, zj);
    if (p === null) throw new Error("history: N is the identity");
    return p;
  });
  return { h: point, offset: Number(offset), w, r, n };
}

/** The blind read as a scalar, inverted in the scalar field. */
function invScalar(r: bigint): bigint {
  const q = Pallas.ORDER;
  let result = 1n;
  let base = r % q;
  let e = q - 2n;
  while (e > 0n) {
    if (e & 1n) result = (result * base) % q;
    base = (base * base) % q;
    e >>= 1n;
  }
  return result;
}

interface Config {
  policy: PolicyConfig;
  binder: BinderConfig;
  history: HistoryConfig;
  breach: BreachConfig;
  instance: Column<"Instance">;
  packByte: Column<"Advice">;
  packAcc: Column<"Advice">;
  qPackInit: Selector;
  qPackStep: Selector;
}

// ─── Gadget A: policy engine ───

interface PolicyConfig {
  byte: Column<"Advice">;
  active: Column<"Advice">;
  isUpper: Column<"Advice">;
  isLower: Column<"Advice">;
  isDigit: Column<"Advice">;
  isSymbol: Column<"Advice">;
  accLen: Column<"Advice">;
  accUpper: Column<"Advice">;
  accLower: Column<"Advice">;
  accDigit: Column<"Advice">;
  accSymbol: Column<"Advice">;
  cmpCount: Column<"Advice">;
  policyMin: Column<"Fixed">;
  tables: TableColumn[];
  qClassify: Selector;
  qInit: Selector;
  qAcc: Selector;
  qCmp: Selector;
}

function configurePolicy(meta: ConstraintSystem): PolicyConfig {
  const byte = meta.adviceColumn();
  const active = meta.adviceColumn();
  const isUpper = meta.adviceColumn();
  const isLower = meta.adviceColumn();
  const isDigit = meta.adviceColumn();
  const isSymbol = meta.adviceColumn();
  const accLen = meta.adviceColumn();
  const accUpper = meta.adviceColumn();
  const accLower = meta.adviceColumn();
  const accDigit = meta.adviceColumn();
  const accSymbol = meta.adviceColumn();
  const cmpCount = meta.adviceColumn();
  const policyMin = meta.fixedColumn();
  const tUpper = meta.lookupTableColumn();
  const tLower = meta.lookupTableColumn();
  const tDigit = meta.lookupTableColumn();
  const tSymbol = meta.lookupTableColumn();
  const tRange = meta.lookupTableColumn();
  const qClassify = meta.selector();
  const qInit = meta.selector();
  const qAcc = meta.selector();
  const qCmp = meta.complexSelector();
  for (const c of [
    byte,
    accLen,
    accUpper,
    accLower,
    accDigit,
    accSymbol,
    cmpCount,
  ])
    meta.enableEquality(c);

  meta.createGate("active_boolean", (m) => {
    const q = m.querySelector(qClassify);
    const a = m.queryAdvice(active, 0);
    return [mul(mul(q, a), sub(constant(1), a))];
  });
  meta.createGate("flags_boolean", (m) => {
    const q = m.querySelector(qClassify);
    const one = constant(1);
    const iu = m.queryAdvice(isUpper, 0);
    const il = m.queryAdvice(isLower, 0);
    const id = m.queryAdvice(isDigit, 0);
    const is = m.queryAdvice(isSymbol, 0);
    return [iu, il, id, is].map((f) => mul(mul(q, f), sub(one, f)));
  });
  meta.createGate("inactive_is_padding", (m) => {
    const q = m.querySelector(qClassify);
    const a = m.queryAdvice(active, 0);
    const notActive = sub(constant(1), a);
    const b = m.queryAdvice(byte, 0);
    const iu = m.queryAdvice(isUpper, 0);
    const il = m.queryAdvice(isLower, 0);
    const id = m.queryAdvice(isDigit, 0);
    const is = m.queryAdvice(isSymbol, 0);
    return [b, iu, il, id, is].map((x) => mul(mul(q, notActive), x));
  });
  meta.createGate("acc_init", (m) => {
    const q = m.querySelector(qInit);
    const an = m.queryAdvice(accLen, 0);
    const au = m.queryAdvice(accUpper, 0);
    const al = m.queryAdvice(accLower, 0);
    const ad = m.queryAdvice(accDigit, 0);
    const as = m.queryAdvice(accSymbol, 0);
    const a = m.queryAdvice(active, 0);
    const iu = m.queryAdvice(isUpper, 0);
    const il = m.queryAdvice(isLower, 0);
    const id = m.queryAdvice(isDigit, 0);
    const is = m.queryAdvice(isSymbol, 0);
    return [
      mul(q, sub(an, a)),
      mul(q, sub(au, iu)),
      mul(q, sub(al, il)),
      mul(q, sub(ad, id)),
      mul(q, sub(as, is)),
    ];
  });
  meta.createGate("active_prefix", (m) => {
    const q = m.querySelector(qAcc);
    const prev = m.queryAdvice(active, -1);
    const cur = m.queryAdvice(active, 0);
    return [mul(mul(q, sub(constant(1), prev)), cur)];
  });
  meta.createGate("acc_step", (m) => {
    const q = m.querySelector(qAcc);
    const step = (acc: Column<"Advice">, flag: Column<"Advice">) =>
      sub(
        sub(m.queryAdvice(acc, 0), m.queryAdvice(acc, -1)),
        m.queryAdvice(flag, 0),
      );
    return [
      mul(q, step(accLen, active)),
      mul(q, step(accUpper, isUpper)),
      mul(q, step(accLower, isLower)),
      mul(q, step(accDigit, isDigit)),
      mul(q, step(accSymbol, isSymbol)),
    ];
  });
  for (const [flag, table, def] of [
    [isUpper, tUpper, 65],
    [isLower, tLower, 97],
    [isDigit, tDigit, 48],
    [isSymbol, tSymbol, 33],
  ] as const) {
    meta.lookup((m) => {
      const b = m.queryAdvice(byte, 0);
      const a = m.queryAdvice(active, 0);
      const f = m.queryAdvice(flag, 0);
      const cond = mul(a, f);
      const val = add(mul(cond, b), mul(sub(constant(1), cond), constant(def)));
      return [[val, table]];
    });
  }
  meta.lookup((m) => [[m.queryAdvice(byte, 0), tRange]]);
  meta.lookup((m) => {
    const b = m.queryAdvice(byte, 0);
    const a = m.queryAdvice(active, 0);
    return [[mul(a, sub(b, constant(1))), tRange]];
  });
  meta.lookup((m) => {
    const q = m.querySelector(qCmp);
    const count = m.queryAdvice(cmpCount, 0);
    const min = m.queryFixed(policyMin);
    return [[mul(q, sub(count, min)), tRange]];
  });
  return {
    byte,
    active,
    isUpper,
    isLower,
    isDigit,
    isSymbol,
    accLen,
    accUpper,
    accLower,
    accDigit,
    accSymbol,
    cmpCount,
    policyMin,
    tables: [tUpper, tLower, tDigit, tSymbol, tRange],
    qClassify,
    qInit,
    qAcc,
    qCmp,
  };
}

const range = (a: number, b: number): number[] =>
  Array.from({ length: b - a + 1 }, (_, i) => a + i);

const SYMBOLS = [
  ...range(33, 47),
  ...range(58, 64),
  ...range(91, 96),
  ...range(123, 126),
];

function classify(b: number): [boolean, boolean, boolean, boolean] {
  return [
    b >= 65 && b <= 90,
    b >= 97 && b <= 122,
    b >= 48 && b <= 57,
    SYMBOLS.includes(b),
  ];
}

function synthesizePolicy(
  config: PolicyConfig,
  policy: PolicyParams,
  layouter: Layouter,
  password: Value[],
  active: Value[],
): AssignedCell[] {
  const tableValues = [
    range(65, 90),
    range(97, 122),
    range(48, 57),
    SYMBOLS,
    range(0, 255),
  ];
  config.tables.forEach((column, t) =>
    layouter.assignTable((table) =>
      tableValues[t].forEach((v, i) => table.assignCell(column, i, BigInt(v))),
    ),
  );

  return layouter.assignRegion((region) => {
    let last: Value[] = [0n, 0n, 0n, 0n, 0n];
    let lastCells: AssignedCell[] = [];
    const byteCells: AssignedCell[] = [];
    for (let i = 0; i < MAX_PASSWORD_LEN; i++) {
      region.enableSelector(config.qClassify, i);
      region.enableSelector(i === 0 ? config.qInit : config.qAcc, i);
      byteCells.push(region.assignAdvice(config.byte, i, () => password[i]));
      region.assignAdvice(config.active, i, () => active[i]);
      const flags: Value[] =
        password[i] === undefined || active[i] === undefined
          ? [undefined, undefined, undefined, undefined]
          : active[i] === 0n
            ? [0n, 0n, 0n, 0n]
            : classify(Number(password[i])).map((f) => (f ? 1n : 0n));
      [config.isUpper, config.isLower, config.isDigit, config.isSymbol].forEach(
        (col, k) => region.assignAdvice(col, i, () => flags[k]),
      );
      const increments = [active[i], ...flags];
      const accCols = [
        config.accLen,
        config.accUpper,
        config.accLower,
        config.accDigit,
        config.accSymbol,
      ];
      lastCells = [];
      for (let k = 0; k < 5; k++) {
        const value =
          i === 0
            ? increments[k]
            : vzip([last[k], increments[k]], (a, b) => Fp.add(a, b));
        last[k] = value;
        lastCells.push(region.assignAdvice(accCols[k], i, () => value));
      }
      last = [...last];
    }
    const minimums = [
      policy.minLength,
      policy.minUpper,
      policy.minLower,
      policy.minDigit,
      policy.minSymbol,
    ];
    lastCells.forEach((count, k) => {
      const row = MAX_PASSWORD_LEN + k;
      region.enableSelector(config.qCmp, row);
      count.copyAdvice(region, config.cmpCount, row);
      region.assignFixed(config.policyMin, row, BigInt(minimums[k]));
    });
    return byteCells;
  });
}

// ─── Gadget C: opaque binder ───

interface BinderConfig {
  ecc: EccConfig;
  poseidon: Pow5Config;
  inputCol: Column<"Advice">;
  qHtcBind: Selector;
  rangeCheckTable: TableColumn;
}

function configureBinder(meta: ConstraintSystem): BinderConfig {
  const advices = Array.from({ length: 10 }, () => meta.adviceColumn());
  for (const c of advices) meta.enableEquality(c);
  const inputCol = meta.adviceColumn();
  meta.enableEquality(inputCol);
  const lookupTable = meta.lookupTableColumn();
  const lagrangeCoeffs = Array.from({ length: 8 }, () => meta.fixedColumn());
  const constants = meta.fixedColumn();
  meta.enableConstant(constants);
  const rangeCheck = LookupRangeCheckConfig.configure(
    meta,
    advices[9],
    lookupTable,
    10,
  );
  const ecc = EccConfig.configure(meta, advices, lagrangeCoeffs, rangeCheck);
  const state = Array.from({ length: 3 }, () => meta.adviceColumn());
  const partialSbox = meta.adviceColumn();
  const rcA = Array.from({ length: 3 }, () => meta.fixedColumn());
  const rcB = Array.from({ length: 3 }, () => meta.fixedColumn());
  for (const c of [...state, partialSbox]) meta.enableEquality(c);
  meta.enableConstant(rcB[0]);
  const poseidon = Pow5Config.configure(meta, state, partialSbox, rcA, rcB);
  const qHtcBind = meta.selector();
  meta.createGate("htc_bind", (m) => {
    const q = m.querySelector(qHtcBind);
    const u = m.queryAdvice(inputCol, 0);
    const offset = m.queryAdvice(inputCol, 1);
    const x = m.queryAdvice(inputCol, 2);
    return [mul(q, sub(sub(x, u), offset))];
  });
  return { ecc, poseidon, inputCol, qHtcBind, rangeCheckTable: lookupTable };
}

interface BinderOutput {
  mX: AssignedCell;
  mY: AssignedCell;
  uHash: AssignedCell;
  pwFeCells: AssignedCell[];
}

function packChunk(chunk: Value[]): Value {
  if (chunk.some((b) => b === undefined)) return undefined;
  let acc = 0n;
  let shift = 1n;
  for (const b of chunk as bigint[]) {
    acc = Fp.add(acc, Fp.mul(b, shift));
    shift = Fp.mul(shift, 256n);
  }
  return acc;
}

function synthesizeBinder(
  config: BinderConfig,
  layouter: Layouter,
  password: Value[],
  blind: Value,
  hP: Point | undefined,
  htcOffset: Value,
): BinderOutput {
  layouter.assignTable((table) => {
    for (let i = 0; i < 1 << 10; i++)
      table.assignCell(config.rangeCheckTable, i, BigInt(i));
  });
  const fes: Value[] = [];
  for (let i = 0; i < password.length; i += BYTES_PER_FE)
    fes.push(packChunk(password.slice(i, i + BYTES_PER_FE)));
  const feCells = fes.map((fe) =>
    layouter.assignRegion((region) =>
      region.assignAdvice(config.inputCol, 0, () => fe),
    ),
  );
  let uHash = config.poseidon.hash2(layouter, [feCells[0], feCells[1]]);
  for (let i = 2; i < feCells.length; i++)
    uHash = config.poseidon.hash2(layouter, [uHash, feCells[i]]);

  const ecc = new EccChip(config.ecc);
  const hPoint = ecc.witnessNonIdentity(layouter, hP);
  const offsetCell = layouter.assignRegion((region) => {
    region.enableSelector(config.qHtcBind, 0);
    uHash.copyAdvice(region, config.inputCol, 0);
    const cell = region.assignAdvice(config.inputCol, 1, () => htcOffset);
    hPoint.x.copyAdvice(region, config.inputCol, 2);
    return cell;
  });
  config.ecc.lookup.copyShortCheck(layouter, offsetCell, HTC_TRY_BITS);

  const blindCell = layouter.assignRegion((region) =>
    region.assignAdvice(config.inputCol, 0, () => blind),
  );
  const m = ecc.mul(layouter, blindCell, hPoint);
  return { mX: m.x, mY: m.y, uHash, pwFeCells: feCells };
}

// ─── Gadget H: history tags ───

interface HistoryConfig {
  ecc: EccConfig;
  poseidon: Pow5Config;
  u: Column<"Advice">;
  lt: Column<"Advice">;
  w: Column<"Advice">;
  wInv: Column<"Advice">;
  acc: Column<"Advice">;
  idx: Column<"Fixed">;
  qScan: Selector;
  qScanStep: Selector;
  qScanFirst: Selector;
  qBind: Selector;
}

function configureHistory(
  meta: ConstraintSystem,
  ecc: EccConfig,
  poseidon: Pow5Config,
): HistoryConfig {
  const [u, lt, w, wInv, acc] = [0, 1, 2, 3, 4].map((i) => ecc.advices[i]);
  const idx = meta.fixedColumn();
  const qScan = meta.selector();
  const qScanStep = meta.selector();
  const qScanFirst = meta.selector();
  const qBind = meta.selector();
  const one = () => constant(1);
  meta.createGate("history scan", (m) => {
    const q = m.querySelector(qScan);
    const uq = m.queryAdvice(u, 0);
    const ltq = m.queryAdvice(lt, 0);
    const wq = m.queryAdvice(w, 0);
    const wInvQ = m.queryAdvice(wInv, 0);
    const x = add(uq, m.queryFixed(idx));
    const rhs = mul(constant(NON_SQUARE), add(mul(mul(x, x), x), constant(5)));
    return [
      mul(mul(q, ltq), sub(one(), ltq)),
      mul(mul(q, ltq), sub(mul(wq, wq), rhs)),
      mul(mul(q, ltq), sub(mul(wq, wInvQ), one())),
    ];
  });
  meta.createGate("history scan step", (m) => {
    const q = m.querySelector(qScanStep);
    const uCur = m.queryAdvice(u, 0);
    const uPrev = m.queryAdvice(u, -1);
    const ltCur = m.queryAdvice(lt, 0);
    const ltPrev = m.queryAdvice(lt, -1);
    const accCur = m.queryAdvice(acc, 0);
    const accPrev = m.queryAdvice(acc, -1);
    return [
      mul(q, sub(uCur, uPrev)),
      mul(mul(q, ltCur), sub(one(), ltPrev)),
      mul(q, sub(sub(accCur, accPrev), ltCur)),
    ];
  });
  meta.createGate("history scan first", (m) => {
    const q = m.querySelector(qScanFirst);
    const ltq = m.queryAdvice(lt, 0);
    const accq = m.queryAdvice(acc, 0);
    return [mul(q, sub(accq, ltq))];
  });
  meta.createGate("history bind", (m) => {
    const q = m.querySelector(qBind);
    const uq = m.queryAdvice(u, 0);
    const offset = m.queryAdvice(lt, 0);
    const x = m.queryAdvice(w, 0);
    const y = m.queryAdvice(wInv, 0);
    const h = m.queryAdvice(acc, 0);
    const r = m.queryAdvice(lt, 1);
    const rInv = m.queryAdvice(w, 1);
    return [
      mul(q, sub(sub(x, uq), offset)),
      mul(q, sub(y, mul(constant(2), h))),
      mul(q, sub(mul(r, rInv), one())),
    ];
  });
  return {
    ecc,
    poseidon,
    u,
    lt,
    w,
    wInv,
    acc,
    idx,
    qScan,
    qScanStep,
    qScanFirst,
    qBind,
  };
}

interface DomainTag {
  zX: AssignedCell;
  zY: AssignedCell;
  t: AssignedCell;
}

const inv0 = (v: bigint): bigint => (v === 0n ? 0n : Fp.inv(v));

function synthesizeHistory(
  config: HistoryConfig,
  layouter: Layouter,
  d: AssignedCell,
  uC: AssignedCell,
  domains: AssignedCell[],
  witness: HistoryTagWitness | undefined,
): { bX: AssignedCell; bY: AssignedCell; tags: DomainTag[] } {
  const u = config.poseidon.hash2(layouter, [d, uC]);
  const ecc = new EccChip(config.ecc);
  const hPoint = ecc.witnessNonIdentity(layouter, witness?.h);

  const count = layouter.assignRegion((region) => {
    let accCell: AssignedCell | null = null;
    for (let i = 0; i < TRIES; i++) {
      region.enableSelector(config.qScan, i);
      if (i === 0) {
        region.enableSelector(config.qScanFirst, i);
        u.copyAdvice(region, config.u, i);
      } else {
        region.enableSelector(config.qScanStep, i);
        region.assignAdvice(config.u, i, () => u.value);
      }
      region.assignFixed(config.idx, i, BigInt(i));
      const below =
        witness === undefined ? undefined : i < witness.offset ? 1n : 0n;
      const wi = witness === undefined ? undefined : (witness.w[i] ?? 0n);
      region.assignAdvice(config.lt, i, () => below);
      region.assignAdvice(config.w, i, () => wi);
      region.assignAdvice(config.wInv, i, () => vmap(wi, inv0));
      const c =
        witness === undefined
          ? undefined
          : BigInt(Math.min(witness.offset, i + 1));
      accCell = region.assignAdvice(config.acc, i, () => c);
    }
    return accCell as AssignedCell;
  });

  const { hCell, rCell } = layouter.assignRegion((region) => {
    region.enableSelector(config.qBind, 0);
    u.copyAdvice(region, config.u, 0);
    count.copyAdvice(region, config.lt, 0);
    hPoint.x.copyAdvice(region, config.w, 0);
    hPoint.y.copyAdvice(region, config.wInv, 0);
    const half = vmap(hPoint.y.value, (y) => Fp.mul(y, Fp.inv(2n)));
    const hCell = region.assignAdvice(config.acc, 0, () => half);
    const r = witness?.r;
    const rCell = region.assignAdvice(config.lt, 1, () => r);
    region.assignAdvice(config.w, 1, () => vmap(r, inv0));
    return { hCell, rCell };
  });

  const running = config.ecc.lookup.copyCheck(
    layouter,
    hCell,
    HALF_WORDS,
    false,
  );
  config.ecc.lookup.copyShortCheck(
    layouter,
    running[HALF_WORDS],
    HALF_TOP_BITS,
  );

  const b = ecc.mul(layouter, rCell, hPoint);
  const tags: DomainTag[] = domains.map((c, j) => {
    const nPoint = ecc.witnessNonIdentity(layouter, witness?.n[j]);
    const z = ecc.mul(layouter, rCell, nPoint);
    const cu = config.poseidon.hash2(layouter, [c, u]);
    const t = config.poseidon.hash2(layouter, [cu, nPoint.x]);
    return { zX: z.x, zY: z.y, t };
  });
  return { bX: b.x, bY: b.y, tags };
}

// ─── Gadget D: breach Bloom non-membership ───

interface BreachConfig {
  poseidon: Pow5Config;
  poseidonInput: Column<"Advice">;
  bit: Column<"Advice">;
  pow: Column<"Fixed">;
  acc: Column<"Advice">;
  qBit: Selector;
  qAccInit: Selector;
  qAccStep: Selector;
  ipow: Column<"Fixed">;
  iacc: Column<"Advice">;
  qIaccInit: Selector;
  qIaccStep: Selector;
  idx: Column<"Advice">;
  lbit: Column<"Advice">;
  active: Column<"Advice">;
  tableIdx: TableColumn;
  tableBit: TableColumn;
  prod: Column<"Advice">;
  qProdInit: Selector;
  qProdStep: Selector;
  qNonmember: Selector;
}

function configureBreach(meta: ConstraintSystem): BreachConfig {
  const poseidonInput = meta.adviceColumn();
  const bit = meta.adviceColumn();
  const pow = meta.fixedColumn();
  const acc = meta.adviceColumn();
  const ipow = meta.fixedColumn();
  const iacc = meta.adviceColumn();
  const idx = meta.adviceColumn();
  const lbit = meta.adviceColumn();
  const active = meta.adviceColumn();
  const prod = meta.adviceColumn();
  for (const c of [poseidonInput, bit, acc, iacc, idx, lbit, prod])
    meta.enableEquality(c);
  const tableIdx = meta.lookupTableColumn();
  const tableBit = meta.lookupTableColumn();
  const state = Array.from({ length: 3 }, () => meta.adviceColumn());
  const partialSbox = meta.adviceColumn();
  const rcA = Array.from({ length: 3 }, () => meta.fixedColumn());
  const rcB = Array.from({ length: 3 }, () => meta.fixedColumn());
  for (const c of [...state, partialSbox]) meta.enableEquality(c);
  meta.enableConstant(rcB[0]);
  const poseidon = Pow5Config.configure(meta, state, partialSbox, rcA, rcB);
  const qBit = meta.selector();
  const qAccInit = meta.selector();
  const qAccStep = meta.selector();
  const qIaccInit = meta.selector();
  const qIaccStep = meta.selector();
  const qProdInit = meta.selector();
  const qProdStep = meta.selector();
  const qNonmember = meta.selector();
  const one = constant(1);

  meta.createGate("bit_boolean", (m) => {
    const q = m.querySelector(qBit);
    const b = m.queryAdvice(bit, 0);
    return [mul(mul(q, b), sub(one, b))];
  });
  meta.createGate("acc_init", (m) => {
    const q = m.querySelector(qAccInit);
    const b = m.queryAdvice(bit, 0);
    const p = m.queryFixed(pow);
    const a = m.queryAdvice(acc, 0);
    return [mul(q, sub(a, mul(b, p)))];
  });
  meta.createGate("acc_step", (m) => {
    const q = m.querySelector(qAccStep);
    const b = m.queryAdvice(bit, 0);
    const p = m.queryFixed(pow);
    const aPrev = m.queryAdvice(acc, -1);
    const aCur = m.queryAdvice(acc, 0);
    return [mul(q, sub(sub(aCur, aPrev), mul(b, p)))];
  });
  meta.createGate("iacc_init", (m) => {
    const q = m.querySelector(qIaccInit);
    const b = m.queryAdvice(bit, 0);
    const p = m.queryFixed(ipow);
    const a = m.queryAdvice(iacc, 0);
    return [mul(q, sub(a, mul(b, p)))];
  });
  meta.createGate("iacc_step", (m) => {
    const q = m.querySelector(qIaccStep);
    const b = m.queryAdvice(bit, 0);
    const p = m.queryFixed(ipow);
    const aPrev = m.queryAdvice(iacc, -1);
    const aCur = m.queryAdvice(iacc, 0);
    return [mul(q, sub(sub(aCur, aPrev), mul(b, p)))];
  });
  const mConst = constant(BLOOM_M);
  meta.lookup((m) => {
    const a = m.queryAdvice(active, 0);
    const i = m.queryAdvice(idx, 0);
    const b = m.queryAdvice(lbit, 0);
    const idxVal = add(mul(a, i), mul(sub(one, a), mConst));
    const bitVal = mul(a, b);
    return [
      [idxVal, tableIdx],
      [bitVal, tableBit],
    ];
  });
  meta.createGate("prod_init", (m) => {
    const q = m.querySelector(qProdInit);
    const b = m.queryAdvice(lbit, 0);
    const p = m.queryAdvice(prod, 0);
    return [mul(q, sub(p, b))];
  });
  meta.createGate("prod_step", (m) => {
    const q = m.querySelector(qProdStep);
    const b = m.queryAdvice(lbit, 0);
    const pPrev = m.queryAdvice(prod, -1);
    const pCur = m.queryAdvice(prod, 0);
    return [mul(q, sub(pCur, mul(pPrev, b)))];
  });
  meta.createGate("nonmember", (m) => {
    const q = m.querySelector(qNonmember);
    const p = m.queryAdvice(prod, 0);
    return [mul(q, p)];
  });
  return {
    poseidon,
    poseidonInput,
    bit,
    pow,
    acc,
    qBit,
    qAccInit,
    qAccStep,
    ipow,
    iacc,
    qIaccInit,
    qIaccStep,
    idx,
    lbit,
    active,
    tableIdx,
    tableBit,
    prod,
    qProdInit,
    qProdStep,
    qNonmember,
  };
}

function bitOf(h: bigint, j: number): bigint {
  return (h >> BigInt(j)) & 1n;
}

function synthesizeBreach(
  config: BreachConfig,
  layouter: Layouter,
  filterBits: number[],
  inputCells: AssignedCell[],
): void {
  layouter.assignTable((table) => {
    for (let i = 0; i < BLOOM_M; i++) {
      table.assignCell(config.tableIdx, i, BigInt(i));
      table.assignCell(config.tableBit, i, BigInt(filterBits[i]));
    }
    table.assignCell(config.tableIdx, BLOOM_M, BigInt(BLOOM_M));
    table.assignCell(config.tableBit, BLOOM_M, 0n);
  });
  const bound = inputCells.map((c) =>
    layouter.assignRegion((region) =>
      c.copyAdvice(region, config.poseidonInput, 0),
    ),
  );
  let hash = config.poseidon.hash2(layouter, [bound[0], bound[1]]);
  for (let i = 2; i < bound.length; i++)
    hash = config.poseidon.hash2(layouter, [hash, bound[i]]);
  const hashVal = hash.value;

  const bitCells = layouter.assignRegion((region) => {
    const cells: AssignedCell[] = [];
    let accPrev: Value = 0n;
    let powJ = 1n;
    let lastAcc: AssignedCell | null = null;
    for (let j = 0; j < HASH_BITS; j++) {
      region.enableSelector(config.qBit, j);
      region.assignFixed(config.pow, j, powJ);
      const bitV = vmap(hashVal, (h) => bitOf(h, j));
      cells.push(region.assignAdvice(config.bit, j, () => bitV));
      const pj = powJ;
      const term = vmap(bitV, (b) => Fp.mul(b, pj));
      let accV: Value;
      if (j === 0) {
        region.enableSelector(config.qAccInit, j);
        accV = term;
      } else {
        region.enableSelector(config.qAccStep, j);
        accV = vzip([accPrev, term], (a, t) => Fp.add(a, t));
      }
      const v = accV;
      lastAcc = region.assignAdvice(config.acc, j, () => v);
      accPrev = accV;
      powJ = Fp.add(powJ, powJ);
    }
    region.constrainEqual((lastAcc as AssignedCell).cell, hash.cell);
    return cells;
  });

  const b = BREACH_PARAMS.indexBits;
  const idxCells = layouter.assignRegion((region) => {
    const out: AssignedCell[] = [];
    let row = 0;
    for (let i = 0; i < BREACH_PARAMS.k; i++) {
      let iaccPrev: Value = 0n;
      let ipow = 1n;
      let last: AssignedCell | null = null;
      for (let l = 0; l < b; l++) {
        const bc = bitCells[i * b + l].copyAdvice(region, config.bit, row);
        region.assignFixed(config.ipow, row, ipow);
        const ip = ipow;
        const term = vmap(bc.value, (v) => Fp.mul(v, ip));
        let v: Value;
        if (l === 0) {
          region.enableSelector(config.qIaccInit, row);
          v = term;
        } else {
          region.enableSelector(config.qIaccStep, row);
          v = vzip([iaccPrev, term], (a, t) => Fp.add(a, t));
        }
        const value = v;
        last = region.assignAdvice(config.iacc, row, () => value);
        iaccPrev = v;
        ipow = Fp.add(ipow, ipow);
        row += 1;
      }
      out.push(last as AssignedCell);
    }
    return out;
  });

  layouter.assignRegion((region) => {
    let prodPrev: Value = 0n;
    for (let i = 0; i < BREACH_PARAMS.k; i++) {
      region.assignAdvice(config.active, i, () => 1n);
      idxCells[i].copyAdvice(region, config.idx, i);
      const lbitV = vmap(hashVal, (h) => {
        let index = 0;
        for (let l = 0; l < b; l++) index |= Number(bitOf(h, i * b + l)) << l;
        return BigInt(filterBits[index]);
      });
      region.assignAdvice(config.lbit, i, () => lbitV);
      let prodV: Value;
      if (i === 0) {
        region.enableSelector(config.qProdInit, i);
        prodV = lbitV;
      } else {
        region.enableSelector(config.qProdStep, i);
        prodV = vzip([prodPrev, lbitV], (p, l) => Fp.mul(p, l));
      }
      const v = prodV;
      region.assignAdvice(config.prod, i, () => v);
      prodPrev = prodV;
    }
    region.enableSelector(config.qNonmember, BREACH_PARAMS.k - 1);
  });
}

// ─── The combined circuit ───

export function configure(meta: ConstraintSystem): Config {
  const policy = configurePolicy(meta);
  const binder = configureBinder(meta);
  const history = configureHistory(meta, binder.ecc, binder.poseidon);
  const breach = configureBreach(meta);
  const instance = meta.instanceColumn();
  meta.enableEquality(instance);
  const packByte = meta.adviceColumn();
  const packAcc = meta.adviceColumn();
  meta.enableEquality(packByte);
  meta.enableEquality(packAcc);
  const qPackInit = meta.selector();
  meta.createGate("pack_init", (m) => {
    const q = m.querySelector(qPackInit);
    const acc = m.queryAdvice(packAcc, 0);
    const byte = m.queryAdvice(packByte, 0);
    return [mul(q, sub(acc, byte))];
  });
  const qPackStep = meta.selector();
  meta.createGate("pack_step", (m) => {
    const q = m.querySelector(qPackStep);
    const accCur = m.queryAdvice(packAcc, 0);
    const accPrev = m.queryAdvice(packAcc, -1);
    const byte = m.queryAdvice(packByte, 0);
    return [mul(q, sub(sub(accCur, mul(accPrev, constant(256))), byte))];
  });
  return {
    policy,
    binder,
    history,
    breach,
    instance,
    packByte,
    packAcc,
    qPackInit,
    qPackStep,
  };
}

/**
 * Synthesize for `shape`, with `witness` when proving and without it for
 * key generation (only the structure and fixed columns are used then).
 */
export function synthesize(
  config: Config,
  layouter: Layouter,
  shape: CircuitShape,
  witness: ZkppWitness | undefined,
): void {
  const password = new Uint8Array(MAX_PASSWORD_LEN);
  if (witness) password.set(witness.password);
  const pwVals: Value[] = Array.from(password, (b) => BigInt(b));
  const passwordLen = witness?.passwordLen ?? 0;
  const active: Value[] = pwVals.map((_, i) => (i < passwordLen ? 1n : 0n));
  const htc = hashToCurveOutside(password);

  const pwByteCells = synthesizePolicy(
    config.policy,
    shape.policy,
    layouter,
    pwVals,
    active,
  );
  const binderOut = synthesizeBinder(
    config.binder,
    layouter,
    pwVals,
    witness ? witness.blind : 1n,
    htc.point,
    htc.offset,
  );

  layouter.assignRegion((region) => {
    let row = 0;
    for (
      let chunkIdx = 0;
      chunkIdx * BYTES_PER_FE < pwByteCells.length;
      chunkIdx++
    ) {
      const chunk = pwByteCells.slice(
        chunkIdx * BYTES_PER_FE,
        (chunkIdx + 1) * BYTES_PER_FE,
      );
      let accVal: Value = 0n;
      for (let i = 0; i < chunk.length; i++) {
        const byteIdx = chunk.length - 1 - i;
        const byteCell = chunk[byteIdx].copyAdvice(
          region,
          config.packByte,
          row,
        );
        const byteVal = byteCell.value;
        if (i === 0) {
          region.enableSelector(config.qPackInit, row);
          accVal = byteVal;
        } else {
          region.enableSelector(config.qPackStep, row);
          accVal = vzip([accVal, byteVal], (a, b) =>
            Fp.add(Fp.mul(a, 256n), b),
          );
        }
        const v = accVal;
        const accCell = region.assignAdvice(config.packAcc, row, () => v);
        if (byteIdx === 0)
          region.constrainEqual(
            accCell.cell,
            binderOut.pwFeCells[chunkIdx].cell,
          );
        row += 1;
      }
    }
  });

  synthesizeBreach(
    config.breach,
    layouter,
    witness?.breachBits ?? new Array(BLOOM_M).fill(0),
    binderOut.pwFeCells,
  );

  const domains = shape.historyDomains;
  const { d, cs } = layouter.assignRegion((region) => {
    const col = config.packByte;
    const dCell = region.assignAdviceFromInstance(config.instance, 2, col, 0);
    const csCells = Array.from({ length: domains }, (_, j) =>
      region.assignAdviceFromInstance(config.instance, 3 + j, col, 1 + j),
    );
    return { d: dCell, cs: csCells };
  });
  const tags = synthesizeHistory(
    config.history,
    layouter,
    d,
    binderOut.uHash,
    cs,
    witness?.history,
  );

  layouter.constrainInstance(binderOut.mX.cell, config.instance, 0);
  layouter.constrainInstance(binderOut.mY.cell, config.instance, 1);
  const exposed = [
    tags.bX,
    tags.bY,
    ...tags.tags.flatMap((t) => [t.zX, t.zY, t.t]),
  ];
  exposed.forEach((cell, i) =>
    layouter.constrainInstance(cell.cell, config.instance, 3 + domains + i),
  );
}
