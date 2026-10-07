/**
 * `create_proof` of halo2_proofs 0.3 over Vesta (IPA), for a circuit and the
 * proving key keygen built for it. Every stage follows the reference, with
 * the randomness drawn in the reference's order from a {@link RandomSource},
 * so a recorded Rust run replays to the same proof bytes. The heavy, order-
 * free work (commitments, the quotient's coset classes, the IPA folding)
 * runs on a {@link ProverPool}; everything that feeds the transcript or
 * draws randomness stays here, in order.
 */
import { Fp } from "../field.js";
import { Vesta, type Point } from "../curve.js";
import { omegaForSize } from "../fft.js";
import { lagrangeToCoeff } from "../domain.js";
import { Transcript } from "../transcript.js";
import type { RandomSource } from "../random.js";
import type { Column, Expression, Selector } from "./expression.js";
import { ConstraintSystem } from "./constraint-system.js";
import { bindRows, compileRows } from "./evaluator.js";
import {
  combineClasses,
  type KeyPolys,
  type QuotientShape,
} from "./quotient.js";
import { LocalPool, type ProverPool } from "./kernel.js";
import { DELTA, type Circuit, type KeygenResult, type Srs } from "./keygen.js";
import { Layouter, type Assignment, type Value } from "./layouter.js";

type Affine = NonNullable<Point>;

/** The prover's view of a key: keygen's values plus coefficient forms. */
export interface ProvingKey {
  /** Names the key in a pool; the verifying key's transcript representative. */
  id: string;
  keygen: KeygenResult;
  srs: Srs;
  /** Fixed, permutation and Lagrange-basis polynomials, coefficient form. */
  polys: KeyPolys;
  shape: QuotientShape;
}

/** Derive the coefficient forms and the quotient shape keygen does not keep. */
export function provingKey(keygen: KeygenResult, srs: Srs): ProvingKey {
  const { k, extendedK: eK, cs } = keygen;
  const n = 1 << k;
  const toPoly = (v: bigint[]) => lagrangeToCoeff(v, k);
  const bf = cs.blindingFactors();
  const basis = (rows: number[]) => {
    const v = new Array<bigint>(n).fill(0n);
    for (const r of rows) v[r] = 1n;
    return toPoly(v);
  };
  const gatePolys = cs.gates.flatMap((g) => g.polys);
  const lookupRoots: Expression[] = [];
  const lookupSlots = cs.lookups.map((l) => ({
    input: l.inputExpressions.map((e) => lookupRoots.push(e) - 1),
    table: l.tableExpressions.map((e) => lookupRoots.push(e) - 1),
  }));
  return {
    id: keygen.transcriptRepr.toString(16),
    keygen,
    srs,
    polys: {
      fixed: keygen.fixed.map(toPoly),
      sigma: keygen.sigmas.map(toPoly),
      l0: basis([0]),
      lBlind: basis(Array.from({ length: bf }, (_, i) => n - 1 - i)),
      lLast: basis([n - bf - 1]),
    },
    shape: {
      k,
      extendedK: eK,
      blindingFactors: bf,
      chunkLen: cs.degree() - 2,
      permColumns: cs.permutation.map((c) => ({
        type: c.type,
        index: c.index,
      })),
      program: compileRows([...gatePolys, ...lookupRoots]),
      gateCount: gatePolys.length,
      lookupSlots,
      delta: DELTA,
    },
  };
}

class WitnessCollection implements Assignment {
  readonly advice: bigint[][];

  constructor(
    cs: ConstraintSystem,
    n: number,
    private readonly usableRows: number,
    private readonly instance: bigint[][],
  ) {
    this.advice = Array.from({ length: cs.numAdvice }, () =>
      new Array(n).fill(0n),
    );
  }

  private usable(row: number): void {
    if (row < 0 || row >= this.usableRows)
      throw new Error("not enough rows available");
  }

  enableSelector(_s: Selector, _row: number): void {}

  queryInstance(column: Column<"Instance">, row: number): Value {
    this.usable(row);
    return this.instance[column.index][row];
  }

  assignAdvice(
    column: Column<"Advice">,
    row: number,
    value: () => Value,
  ): void {
    this.usable(row);
    const v = value();
    if (v === undefined) throw new Error("unknown advice value while proving");
    this.advice[column.index][row] = Fp.mod(v);
  }

  assignFixed(): void {}
  copy(): void {}
  fillFromRow(): void {}
}

function evalPolynomial(coeff: bigint[], point: bigint): bigint {
  let acc = 0n;
  for (let i = coeff.length - 1; i >= 0; i--)
    acc = Fp.add(Fp.mul(acc, point), coeff[i]);
  return acc;
}

function kateDivision(a: bigint[], point: bigint): bigint[] {
  const b = Fp.neg(point);
  const lenQ = a.length - 1;
  const q = new Array<bigint>(lenQ).fill(0n);
  let tmp = 0n;
  for (let k = 0; k < lenQ; k++) {
    const lead = Fp.sub(a[a.length - 1 - k], tmp);
    q[lenQ - 1 - k] = lead;
    tmp = Fp.mul(lead, b);
  }
  return q;
}

const innerProduct = (a: bigint[], b: bigint[]): bigint => {
  let acc = 0n;
  for (let i = 0; i < a.length; i++) acc = Fp.add(acc, Fp.mul(a[i], b[i]));
  return acc;
};

export interface ProveOptions {
  /** Scalars absorbed before the verifying key (the operation binding context). */
  context?: bigint[];
  onProgress?: (stage: string, fraction: number) => void;
  /**
   * Where the heavy work runs; the key is loaded into it on first use. The
   * default runs it all on the calling thread.
   */
  pool?: ProverPool;
}

/** Prove `circuit` for the single instance column `instance`. */
export async function createProof<C>(
  pk: ProvingKey,
  circuit: Circuit<C>,
  instance: bigint[],
  rng: RandomSource,
  opts: ProveOptions = {},
): Promise<Uint8Array> {
  const { keygen: kg, srs } = pk;
  const cs = kg.cs;
  const k = kg.k;
  const n = 1 << k;
  const eK = kg.extendedK;
  const qpdRows = (1 << eK) / n;
  const bf = cs.blindingFactors();
  const unusable = n - (bf + 1);
  const random = (): bigint => Fp.fromUniformBytes(rng(64));
  const report = opts.onProgress ?? (() => undefined);

  let pool = opts.pool;
  let own = false;
  if (!pool) {
    pool = new LocalPool();
    own = true;
    await pool.init(srs);
  }
  try {
    if (!pool.hasKey(pk.id)) {
      report("load-key", 0);
      await pool.loadKey(pk.id, { shape: pk.shape, polys: pk.polys }, qpdRows);
    }
    return await prove(pool);
  } finally {
    if (own) pool.close();
  }

  async function prove(pool: ProverPool): Promise<Uint8Array> {
    const t = new Transcript();
    const out: Uint8Array[] = [];
    const writePoint = (p: Affine) => {
      t.commonPoint(p);
      out.push(Vesta.toBytes(p));
    };
    const writeScalar = (s: bigint) => {
      t.commonScalar(s);
      out.push(Fp.toBytes(s));
    };
    /** An MSM result plus its blinding term. */
    const blinded = (p: Point, blind: bigint): Affine => {
      const c = Vesta.add(p, Vesta.scalarMul(blind, srs.w));
      if (c === null) throw new Error("commitment is the identity");
      return c;
    };

    for (const s of opts.context ?? []) t.commonScalar(s);
    t.commonScalar(kg.transcriptRepr);

    // Instance
    const instValues = [new Array<bigint>(n).fill(0n)];
    if (instance.length > unusable) throw new Error("instance too large");
    instance.forEach((v, i) => (instValues[0][i] = Fp.mod(v)));
    const [instCommit] = await pool.msmMany(instValues, "lagrange");
    t.commonPoint(blinded(instCommit, 1n));
    const instPolys = instValues.map((v) => lagrangeToCoeff(v, k));

    // Advice
    report("witness", 0);
    // The config comes from a fresh configure; the constraint system used is
    // the key's, whose selectors are compressed.
    const cs0 = circuit.configure(new ConstraintSystem());
    const witness = new WitnessCollection(cs, n, unusable, instValues);
    circuit.synthesize(cs0, new Layouter(witness, cs.constants));
    const advice = witness.advice;
    for (const col of advice)
      for (let r = unusable; r < n; r++) col[r] = random();
    const adviceBlinds = advice.map(() => random());
    report("commit-advice", 0);
    const committed = await pool.adviceMany(advice, k);
    committed.forEach((c, i) => writePoint(blinded(c.point, adviceBlinds[i])));
    const advicePolys = committed.map((c) => c.poly);

    const valueCols = { fixed: kg.fixed, advice, instance: instValues };

    // Lookups: permuted input and table
    report("lookups", 0);
    const theta = t.squeezeChallenge();
    const { lookupSlots } = pk.shape;
    const lookupRoots = cs.lookups.flatMap((l) => [
      ...l.inputExpressions,
      ...l.tableExpressions,
    ]);
    const foldTheta = (regs: bigint[], outs: Int32Array, at: number[]) => {
      let acc = 0n;
      for (const i of at) acc = Fp.add(Fp.mul(acc, theta), regs[outs[i]]);
      return acc;
    };
    const cins = lookupSlots.map(() => new Array<bigint>(n));
    const ctabs = lookupSlots.map(() => new Array<bigint>(n));
    {
      const prog = compileRows(lookupRoots);
      const rows = bindRows(prog, valueCols, n, 1);
      for (let r = 0; r < n; r++) {
        rows.run(r);
        lookupSlots.forEach((s, i) => {
          cins[i][r] = foldTheta(rows.regs, prog.outputs, s.input);
          ctabs[i][r] = foldTheta(rows.regs, prog.outputs, s.table);
        });
      }
    }
    const cmp = (a: bigint, b: bigint) => (a < b ? -1 : a > b ? 1 : 0);
    const lookups = cs.lookups.map((_, li) => {
      const cin = cins[li];
      const ctab = ctabs[li];
      const pInput = cin.slice(0, unusable).sort(cmp);
      const counts = new Map<bigint, number>();
      for (let i = 0; i < unusable; i++)
        counts.set(ctab[i], (counts.get(ctab[i]) ?? 0) + 1);
      const pTable = new Array<bigint>(unusable).fill(0n);
      const repeated: number[] = [];
      for (let row = 0; row < unusable; row++) {
        if (row === 0 || pInput[row] !== pInput[row - 1]) {
          pTable[row] = pInput[row];
          const left = (counts.get(pInput[row]) ?? 0) - 1;
          if (left < 0) throw new Error("lookup input not in table");
          counts.set(pInput[row], left);
        } else repeated.push(row);
      }
      for (const coeff of [...counts.keys()].sort(cmp))
        for (let c = 0; c < (counts.get(coeff) as number); c++)
          pTable[repeated.pop() as number] = coeff;
      for (let i = 0; i < bf + 1; i++) pInput.push(random());
      for (let i = 0; i < bf + 1; i++) pTable.push(random());
      const inputBlind = random();
      const tableBlind = random();
      return { cin, ctab, pInput, pTable, inputBlind, tableBlind };
    });
    const lookupCommits = await pool.msmMany(
      lookups.flatMap((lk) => [lk.pInput, lk.pTable]),
      "lagrange",
    );
    lookups.forEach((lk, i) => {
      writePoint(blinded(lookupCommits[2 * i], lk.inputBlind));
      writePoint(blinded(lookupCommits[2 * i + 1], lk.tableBlind));
    });

    const beta = t.squeezeChallenge();
    const gamma = t.squeezeChallenge();

    // Permutation grand products
    report("permutation", 0);
    const chunkLen = cs.degree() - 2;
    const permCols = cs.permutation;
    const columnValues = (c: Column) =>
      c.type === "Advice"
        ? advice[c.index]
        : c.type === "Fixed"
          ? kg.fixed[c.index]
          : instValues[c.index];
    const omega = omegaForSize(k);
    const permZ: { z: bigint[]; blind: bigint }[] = [];
    let lastZ = 1n;
    for (let start = 0; start < permCols.length; start += chunkLen) {
      const cols = permCols.slice(start, start + chunkLen);
      const modified = new Array<bigint>(n).fill(1n);
      cols.forEach((c, j) => {
        const values = columnValues(c);
        const sigma = kg.sigmas[start + j];
        for (let i = 0; i < n; i++)
          modified[i] = Fp.mul(
            modified[i],
            Fp.add(Fp.add(values[i], Fp.mul(beta, sigma[i])), gamma),
          );
      });
      Fp.invertMany(modified);
      let deltaOmega = Fp.pow(DELTA, BigInt(start));
      cols.forEach((c) => {
        const values = columnValues(c);
        let cur = deltaOmega;
        for (let i = 0; i < n; i++) {
          modified[i] = Fp.mul(
            modified[i],
            Fp.add(Fp.add(values[i], Fp.mul(cur, beta)), gamma),
          );
          cur = Fp.mul(cur, omega);
        }
        deltaOmega = Fp.mul(deltaOmega, DELTA);
      });
      const z = [lastZ];
      for (let i = 1; i < n; i++) z.push(Fp.mul(z[i - 1], modified[i - 1]));
      for (let i = n - bf; i < n; i++) z[i] = random();
      lastZ = z[n - (bf + 1)];
      permZ.push({ z, blind: random() });
    }

    // Lookup grand products
    const lookupZ = lookups.map((lk) => {
      const lp = new Array<bigint>(n);
      for (let i = 0; i < n; i++)
        lp[i] = Fp.mul(Fp.add(beta, lk.pInput[i]), Fp.add(gamma, lk.pTable[i]));
      Fp.invertMany(lp);
      for (let i = 0; i < n; i++)
        lp[i] = Fp.mul(
          lp[i],
          Fp.mul(Fp.add(lk.cin[i], beta), Fp.add(lk.ctab[i], gamma)),
        );
      const z = [1n];
      for (let i = 0; i < n - bf - 1; i++)
        z.push(Fp.mul(z[z.length - 1], lp[i]));
      for (let i = 0; i < bf; i++) z.push(random());
      return { z, blind: random() };
    });

    // Vanishing argument: random polynomial
    const randomPoly = Array.from({ length: n }, () => random());
    const randomBlind = random();
    const [zCommits, [randomCommit]] = await Promise.all([
      pool.msmMany(
        [...permZ, ...lookupZ].map((p) => p.z),
        "lagrange",
      ),
      pool.msmMany([randomPoly], "g"),
    ]);
    [...permZ, ...lookupZ].forEach((p, i) =>
      writePoint(blinded(zCommits[i], p.blind)),
    );
    writePoint(blinded(randomCommit, randomBlind));
    const y = t.squeezeChallenge();

    // Quotient
    report("quotient", 0);
    const permZPolys = permZ.map((p) => lagrangeToCoeff(p.z, k));
    const lookupPolys = lookups.map((lk, i) => ({
      ap: lagrangeToCoeff(lk.pInput, k),
      sp: lagrangeToCoeff(lk.pTable, k),
      z: lagrangeToCoeff(lookupZ[i].z, k),
    }));
    const quotientDegree = kg.domainDegree - 1;
    report("quotient-eval", 0);
    const ws = await pool.quotient(
      pk.id,
      {
        advice: advicePolys,
        instance: instPolys,
        permZ: permZPolys,
        lookups: lookupPolys,
      },
      { theta, beta, gamma, y },
    );
    report("quotient-commit", 0);
    const hCoeff = combineClasses(ws, k, quotientDegree);
    const hPieces: bigint[][] = [];
    for (let off = 0; off < hCoeff.length; off += n)
      hPieces.push(hCoeff.slice(off, off + n));
    const hBlinds = hPieces.map(() => random());
    const hCommits = await pool.msmMany(hPieces, "g");
    hCommits.forEach((c, i) => writePoint(blinded(c, hBlinds[i])));
    const x = t.squeezeChallenge();
    const xn = Fp.pow(x, BigInt(n));

    // Evaluations
    report("evaluate", 0);
    const omegaInv = Fp.inv(omega);
    const rotate = (r: number) =>
      r >= 0
        ? Fp.mul(x, Fp.pow(omega, BigInt(r)))
        : Fp.mul(x, Fp.pow(omegaInv, BigInt(-r)));
    for (const [c, r] of cs.instanceQueries)
      writeScalar(evalPolynomial(instPolys[c.index], rotate(r)));
    for (const [c, r] of cs.adviceQueries)
      writeScalar(evalPolynomial(advicePolys[c.index], rotate(r)));
    for (const [c, r] of cs.fixedQueries)
      writeScalar(evalPolynomial(pk.polys.fixed[c.index], rotate(r)));
    writeScalar(evalPolynomial(randomPoly, x));
    for (const s of pk.polys.sigma) writeScalar(evalPolynomial(s, x));
    const xNext = rotate(1);
    const xLast = rotate(-(bf + 1));
    const xPrev = rotate(-1);
    permZPolys.forEach((p, c) => {
      writeScalar(evalPolynomial(p, x));
      writeScalar(evalPolynomial(p, xNext));
      if (c < permZPolys.length - 1) writeScalar(evalPolynomial(p, xLast));
    });
    for (const lp of lookupPolys) {
      writeScalar(evalPolynomial(lp.z, x));
      writeScalar(evalPolynomial(lp.z, xNext));
      writeScalar(evalPolynomial(lp.ap, x));
      writeScalar(evalPolynomial(lp.ap, xPrev));
      writeScalar(evalPolynomial(lp.sp, x));
    }

    // Multiopen
    report("multiopen", 0);
    interface Query {
      id: string;
      poly: bigint[];
      point: bigint;
      blind: bigint;
    }
    const queries: Query[] = [];
    for (const [c, r] of cs.instanceQueries)
      queries.push({
        id: `i${c.index}`,
        poly: instPolys[c.index],
        point: rotate(r),
        blind: 1n,
      });
    for (const [c, r] of cs.adviceQueries)
      queries.push({
        id: `a${c.index}`,
        poly: advicePolys[c.index],
        point: rotate(r),
        blind: adviceBlinds[c.index],
      });
    permZPolys.forEach((p, c) => {
      queries.push({ id: `pz${c}`, poly: p, point: x, blind: permZ[c].blind });
      queries.push({
        id: `pz${c}`,
        poly: p,
        point: xNext,
        blind: permZ[c].blind,
      });
    });
    for (let c = permZPolys.length - 2; c >= 0; c--)
      queries.push({
        id: `pz${c}`,
        poly: permZPolys[c],
        point: xLast,
        blind: permZ[c].blind,
      });
    lookupPolys.forEach((lp, i) => {
      const lk = lookups[i];
      queries.push({
        id: `lz${i}`,
        poly: lp.z,
        point: x,
        blind: lookupZ[i].blind,
      });
      queries.push({
        id: `la${i}`,
        poly: lp.ap,
        point: x,
        blind: lk.inputBlind,
      });
      queries.push({
        id: `ls${i}`,
        poly: lp.sp,
        point: x,
        blind: lk.tableBlind,
      });
      queries.push({
        id: `la${i}`,
        poly: lp.ap,
        point: xPrev,
        blind: lk.inputBlind,
      });
      queries.push({
        id: `lz${i}`,
        poly: lp.z,
        point: xNext,
        blind: lookupZ[i].blind,
      });
    });
    for (const [c, r] of cs.fixedQueries)
      queries.push({
        id: `f${c.index}`,
        poly: pk.polys.fixed[c.index],
        point: rotate(r),
        blind: 1n,
      });
    pk.polys.sigma.forEach((s, j) =>
      queries.push({ id: `s${j}`, poly: s, point: x, blind: 1n }),
    );
    {
      const hCombined = new Array<bigint>(n).fill(0n);
      let hBlind = 0n;
      let scale = 1n;
      hPieces.forEach((piece, p) => {
        for (let i = 0; i < n; i++)
          hCombined[i] = Fp.add(hCombined[i], Fp.mul(piece[i], scale));
        hBlind = Fp.add(hBlind, Fp.mul(hBlinds[p], scale));
        scale = Fp.mul(scale, xn);
      });
      queries.push({ id: "h", poly: hCombined, point: x, blind: hBlind });
      queries.push({
        id: "random",
        poly: randomPoly,
        point: x,
        blind: randomBlind,
      });
    }

    const x1 = t.squeezeChallenge();
    const x2 = t.squeezeChallenge();
    // construct_intermediate_sets
    const pointIndex = new Map<bigint, number>();
    const commitments = new Map<
      string,
      { poly: bigint[]; blind: bigint; points: number[] }
    >();
    for (const q of queries) {
      if (!pointIndex.has(q.point)) pointIndex.set(q.point, pointIndex.size);
      const pi = pointIndex.get(q.point) as number;
      let entry = commitments.get(q.id);
      if (!entry) {
        entry = { poly: q.poly, blind: q.blind, points: [] };
        commitments.set(q.id, entry);
      }
      entry.points.push(pi);
    }
    const points = [...pointIndex.keys()];
    const setIndex = new Map<string, number>();
    const setOf = new Map<string, number[]>();
    for (const [id, e] of commitments) {
      const s = [...new Set(e.points)].sort((a, b) => a - b);
      setOf.set(id, s);
      const key = s.join(",");
      if (!setIndex.has(key)) setIndex.set(key, setIndex.size);
    }
    const sets: { polys: bigint[][]; blinds: bigint[]; points: bigint[] }[] =
      Array.from({ length: setIndex.size }, () => ({
        polys: [],
        blinds: [],
        points: [],
      }));
    for (const [key, si] of setIndex)
      sets[si].points = key.split(",").map((i) => points[+i]);
    for (const [id, e] of commitments) {
      const si = setIndex.get((setOf.get(id) as number[]).join(",")) as number;
      sets[si].polys.push(e.poly);
      sets[si].blinds.push(e.blind);
    }
    const qPolys = sets.map((s) =>
      s.polys.reduce((q, p) => q.map((v, i) => Fp.add(Fp.mul(v, x1), p[i]))),
    );
    const qBlinds = sets.map((s) =>
      s.blinds.reduce((q, b) => Fp.add(Fp.mul(q, x1), b)),
    );
    let qPrime: bigint[] = [];
    sets.forEach((s, si) => {
      let poly = qPolys[si].slice();
      for (const p of s.points) poly = kateDivision(poly, p);
      while (poly.length < n) poly.push(0n);
      qPrime =
        si === 0 ? poly : qPrime.map((v, i) => Fp.add(Fp.mul(v, x2), poly[i]));
    });
    const qPrimeBlind = random();
    const [qPrimeCommit] = await pool.msmMany([qPrime], "g");
    writePoint(blinded(qPrimeCommit, qPrimeBlind));
    const x3 = t.squeezeChallenge();
    for (const q of qPolys) writeScalar(evalPolynomial(q, x3));
    const x4 = t.squeezeChallenge();
    let pPoly = qPrime.slice();
    let pBlind = qPrimeBlind;
    qPolys.forEach((q, i) => {
      pPoly = pPoly.map((v, j) => Fp.add(Fp.mul(v, x4), q[j]));
      pBlind = Fp.add(Fp.mul(pBlind, x4), qBlinds[i]);
    });

    // IPA opening
    report("ipa", 0);
    const sPoly = Array.from({ length: n }, () => random());
    sPoly[0] = Fp.sub(sPoly[0], evalPolynomial(sPoly, x3));
    const sBlind = random();
    const [sCommit] = await pool.msmMany([sPoly], "g");
    writePoint(blinded(sCommit, sBlind));
    const xi = t.squeezeChallenge();
    const z = t.squeezeChallenge();
    let p = sPoly.map((s, i) => Fp.add(Fp.mul(s, xi), pPoly[i]));
    p[0] = Fp.sub(p[0], evalPolynomial(p, x3));
    let f = Fp.add(Fp.mul(sBlind, xi), pBlind);
    let b: bigint[] = [];
    let cur = 1n;
    for (let i = 0; i < n; i++) {
      b.push(cur);
      cur = Fp.mul(cur, x3);
    }
    let g = srs.g.slice();
    for (let j = 0; j < k; j++) {
      const half = 1 << (k - j - 1);
      const lRand = random();
      const rRand = random();
      const vL = innerProduct(p.slice(half), b.slice(0, half));
      const vR = innerProduct(p.slice(0, half), b.slice(half));
      const [lBase, rBase] = await Promise.all([
        pool.msmPoints(p.slice(half), g.slice(0, half)),
        pool.msmPoints(p.slice(0, half), g.slice(half)),
      ]);
      const L = Vesta.add(
        lBase,
        Vesta.add(
          Vesta.scalarMul(Fp.mul(vL, z), srs.u),
          Vesta.scalarMul(lRand, srs.w),
        ),
      ) as Affine;
      const R = Vesta.add(
        rBase,
        Vesta.add(
          Vesta.scalarMul(Fp.mul(vR, z), srs.u),
          Vesta.scalarMul(rRand, srs.w),
        ),
      ) as Affine;
      writePoint(L);
      writePoint(R);
      const uj = t.squeezeChallenge();
      const ujInv = Fp.inv(uj);
      const np: bigint[] = [];
      const nb: bigint[] = [];
      for (let i = 0; i < half; i++) {
        np.push(Fp.add(p[i], Fp.mul(p[i + half], ujInv)));
        nb.push(Fp.add(b[i], Fp.mul(b[i + half], uj)));
      }
      const ng = await pool.fold(g.slice(0, half), g.slice(half), uj);
      if (ng.some((q) => q === null))
        throw new Error("folded generator is the identity");
      p = np;
      b = nb;
      g = ng as Affine[];
      f = Fp.add(f, Fp.add(Fp.mul(lRand, ujInv), Fp.mul(rRand, uj)));
      report("ipa", (j + 1) / k);
    }
    writeScalar(p[0]);
    writeScalar(f);

    const size = out.reduce((a, c) => a + c.length, 0);
    const proof = new Uint8Array(size);
    let at = 0;
    for (const c of out) {
      proof.set(c, at);
      at += c.length;
    }
    return proof;
  }
}
