/**
 * Key generation of halo2_proofs 0.3 (`keygen_vk` / `keygen_pk`) for a
 * circuit given as `configure` + `synthesize`: the keygen assembly, selector
 * compression, the permutation's sigma polynomials, the fixed and permutation
 * commitments, and the verifying key's pinned text and transcript
 * representative (BLAKE2b-512 "Halo2-Verify-Key" over that text).
 */
import { blake2b } from "@noble/hashes/blake2.js";
import { Fp, FP_MODULUS, FQ_MODULUS } from "../field.js";
import { Vesta, type Point } from "../curve.js";
import { omegaForSize } from "../fft.js";
import type { Column, Selector } from "./expression.js";
import { fieldDebug } from "./expression.js";
import { ConstraintSystem } from "./constraint-system.js";
import { Layouter, type Assignment, type Value } from "./layouter.js";

type Affine = NonNullable<Point>;

/** The commitment key: Lagrange-basis generators and the blinding generator. */
export interface Srs {
  k: number;
  g: Affine[];
  gLagrange: Affine[];
  w: Affine;
  u: Affine;
}

/** `Fp::DELTA = MULTIPLICATIVE_GENERATOR^(2^S)` with generator 5, S = 32. */
export const DELTA = Fp.pow(5n, 1n << 32n);

const sameColumn = (a: Column, b: Column) =>
  a.index === b.index && a.type === b.type;

/** The permutation assembly: cycles of equal cells, halo2 `permutation::keygen`. */
export class PermutationAssembly {
  readonly mapping: [number, number][][];
  private readonly aux: [number, number][][];
  private readonly sizes: number[][];

  constructor(
    n: number,
    readonly columns: Column[],
  ) {
    this.mapping = columns.map((_, i) =>
      Array.from({ length: n }, (_, j) => [i, j] as [number, number]),
    );
    this.aux = columns.map((_, i) =>
      Array.from({ length: n }, (_, j) => [i, j] as [number, number]),
    );
    this.sizes = columns.map(() => new Array(n).fill(1));
  }

  copy(left: Column, leftRow: number, right: Column, rightRow: number): void {
    const l = this.columns.findIndex((c) => sameColumn(c, left));
    const r = this.columns.findIndex((c) => sameColumn(c, right));
    if (l < 0 || r < 0) throw new Error("column not in permutation");
    let lc = this.aux[l][leftRow];
    let rc = this.aux[r][rightRow];
    if (lc[0] === rc[0] && lc[1] === rc[1]) return;
    if (this.sizes[lc[0]][lc[1]] < this.sizes[rc[0]][rc[1]])
      [lc, rc] = [rc, lc];
    this.sizes[lc[0]][lc[1]] += this.sizes[rc[0]][rc[1]];
    let i = rc;
    for (;;) {
      this.aux[i[0]][i[1]] = lc;
      i = this.mapping[i[0]][i[1]];
      if (i[0] === rc[0] && i[1] === rc[1]) break;
    }
    const tmp = this.mapping[l][leftRow];
    this.mapping[l][leftRow] = this.mapping[r][rightRow];
    this.mapping[r][rightRow] = tmp;
  }

  /** The sigma polynomial of each column, Lagrange basis. */
  sigmas(k: number): bigint[][] {
    const n = 1 << k;
    const omega = omegaForSize(k);
    const omegaPowers = [1n];
    for (let j = 1; j < n; j++)
      omegaPowers.push(Fp.mul(omegaPowers[j - 1], omega));
    const deltaOmega: bigint[][] = [];
    let cur = 1n;
    for (let i = 0; i < this.columns.length; i++) {
      const c = cur;
      deltaOmega.push(omegaPowers.map((o) => Fp.mul(o, c)));
      cur = Fp.mul(cur, DELTA);
    }
    return this.mapping.map((row) => row.map(([pi, pj]) => deltaOmega[pi][pj]));
  }
}

/** The keygen assembly: fixed values, selector activations and copies. */
class KeygenAssembly implements Assignment {
  readonly fixed: bigint[][];
  readonly selectors: boolean[][];
  readonly permutation: PermutationAssembly;

  constructor(
    cs: ConstraintSystem,
    private readonly n: number,
    private readonly usableRows: number,
  ) {
    this.fixed = Array.from({ length: cs.numFixed }, () =>
      new Array(n).fill(0n),
    );
    this.selectors = Array.from({ length: cs.numSelectors }, () =>
      new Array(n).fill(false),
    );
    this.permutation = new PermutationAssembly(n, cs.permutation);
  }

  private usable(row: number): void {
    if (row < 0 || row >= this.usableRows)
      throw new Error("not enough rows available");
  }

  enableSelector(selector: Selector, row: number): void {
    this.usable(row);
    this.selectors[selector.index][row] = true;
  }

  queryInstance(_column: Column<"Instance">, row: number): Value {
    this.usable(row);
    return undefined;
  }

  assignAdvice(): void {
    // Keygen does not look at advice values.
  }

  assignFixed(column: Column<"Fixed">, row: number, value: () => Value): void {
    this.usable(row);
    const v = value();
    if (v === undefined)
      throw new Error("unknown fixed value at key generation");
    this.fixed[column.index][row] = Fp.mod(v);
  }

  copy(left: Column, leftRow: number, right: Column, rightRow: number): void {
    this.usable(leftRow);
    this.usable(rightRow);
    this.permutation.copy(left, leftRow, right, rightRow);
  }

  fillFromRow(column: Column<"Fixed">, row: number, value: Value): void {
    this.usable(row);
    if (value === undefined) throw new Error("unknown table default");
    for (let r = row; r < this.usableRows; r++)
      this.fixed[column.index][r] = value;
  }
}

/** A circuit as keygen and the prover see it. */
export interface Circuit<C> {
  configure(meta: ConstraintSystem): C;
  synthesize(config: C, layouter: Layouter): void;
}

export interface KeygenResult {
  cs: ConstraintSystem;
  k: number;
  extendedK: number;
  /** The constraint degree the domain was built for (before selector compression). */
  domainDegree: number;
  /** Fixed columns (selector columns appended), Lagrange basis. */
  fixed: bigint[][];
  /** Sigma polynomials, Lagrange basis, in permutation-column order. */
  sigmas: bigint[][];
  fixedCommitments: Affine[];
  permutationCommitments: Affine[];
  /** Rust `{:?}` of `PinnedVerificationKey`. */
  pinned: string;
  /** The verifying key's transcript representative. */
  transcriptRepr: bigint;
}

/** `EvaluationDomain::new(j, k)`: the extended domain fits the quotient's degree. */
export function extendedK(degree: number, k: number): number {
  const quotientDegree = BigInt(degree - 1);
  let e = k;
  while (1n << BigInt(e) < (1n << BigInt(k)) * quotientDegree) e += 1;
  return e;
}

const pointDebug = (p: Affine): string =>
  `(0x${p.x.toString(16).padStart(64, "0")}, 0x${p.y.toString(16).padStart(64, "0")})`;

/** Commit a Lagrange-basis polynomial with the default blind (one). */
export function commitLagrange(poly: bigint[], srs: Srs): Affine {
  const p = Vesta.add(Vesta.msm(poly, srs.gLagrange), srs.w);
  if (p === null) throw new Error("commitment is the identity");
  return p;
}

/** Keygen up to the commitments: the circuit's fixed and sigma columns. */
export interface KeygenColumns {
  cs: ConstraintSystem;
  k: number;
  extendedK: number;
  domainDegree: number;
  fixed: bigint[][];
  sigmas: bigint[][];
}

/** Synthesize `circuit` for key generation and build its fixed and sigma columns. */
export function keygenColumns<C>(
  circuit: Circuit<C>,
  k: number,
): KeygenColumns {
  const n = 1 << k;
  const cs = new ConstraintSystem();
  const config = circuit.configure(cs);
  const domainDegree = cs.degree();
  const eK = extendedK(domainDegree, k);
  if (n < cs.minimumRows()) throw new Error("not enough rows available");
  const usableRows = n - (cs.blindingFactors() + 1);

  const assembly = new KeygenAssembly(cs, n, usableRows);
  circuit.synthesize(config, new Layouter(assembly, cs.constants));

  const fixed = assembly.fixed.map((c) => c.slice());
  fixed.push(...cs.compressSelectors(assembly.selectors));
  return {
    cs,
    k,
    extendedK: eK,
    domainDegree,
    fixed,
    sigmas: assembly.permutation.sigmas(k),
  };
}

export function keygen<C>(
  circuit: Circuit<C>,
  srs: Srs,
  onProgress?: (fraction: number) => void,
): KeygenResult {
  const columns = keygenColumns(circuit, srs.k);
  const total = columns.fixed.length + columns.sigmas.length;
  let done = 0;
  const commit = (poly: bigint[]) => {
    const c = commitLagrange(poly, srs);
    onProgress?.(++done / total);
    return c;
  };
  return keygenFinish(
    columns,
    columns.fixed.map(commit),
    columns.sigmas.map(commit),
  );
}

/** Unblinded column commitments with keygen's default blind `w` added. */
export function withDefaultBlind(points: Point[], srs: Srs): Affine[] {
  return points.map((p) => {
    const c = Vesta.add(p, srs.w);
    if (c === null) throw new Error("commitment is the identity");
    return c;
  });
}

/**
 * Keygen with the commitments computed by `commitMany` (Σ v_i·gLagrange_i of
 * each column, without the blind); the default blind `w` is added here, so the
 * result equals {@link keygen}.
 */
export async function keygenWith<C>(
  circuit: Circuit<C>,
  srs: Srs,
  commitMany: (polys: bigint[][]) => Promise<Point[]>,
): Promise<KeygenResult> {
  const columns = keygenColumns(circuit, srs.k);
  const blinded = withDefaultBlind(
    await commitMany([...columns.fixed, ...columns.sigmas]),
    srs,
  );
  const f = columns.fixed.length;
  return keygenFinish(columns, blinded.slice(0, f), blinded.slice(f));
}

/**
 * Keygen's result from the columns and their (blinded) commitments: the
 * verifying key's pinned text and transcript representative.
 */
export function keygenFinish(
  columns: KeygenColumns,
  fixedCommitments: Affine[],
  permutationCommitments: Affine[],
): KeygenResult {
  const { cs, k, extendedK: eK, domainDegree, fixed, sigmas } = columns;
  const omega = omegaForSize(k);
  const list = (xs: Affine[]) => `[${xs.map(pointDebug).join(", ")}]`;
  const pinned =
    "PinnedVerificationKey { " +
    `base_modulus: "0x${FQ_MODULUS.toString(16).padStart(64, "0")}", ` +
    `scalar_modulus: "0x${FP_MODULUS.toString(16).padStart(64, "0")}", ` +
    `domain: PinnedEvaluationDomain { k: ${k}, extended_k: ${eK}, omega: ${fieldDebug(omega)} }, ` +
    `cs: ${cs.pinnedDebug()}, ` +
    `fixed_commitments: ${list(fixedCommitments)}, ` +
    `permutation: VerifyingKey { commitments: ${list(permutationCommitments)} } }`;

  const text = new TextEncoder().encode(pinned);
  const len = new Uint8Array(8);
  new DataView(len.buffer).setBigUint64(0, BigInt(text.length), true);
  const digest = blake2b
    .create({
      dkLen: 64,
      personalization: new TextEncoder().encode("Halo2-Verify-Key"),
    })
    .update(len)
    .update(text)
    .digest();
  const transcriptRepr = Fp.fromUniformBytes(digest);

  return {
    cs,
    k,
    extendedK: eK,
    fixed,
    sigmas,
    fixedCommitments,
    permutationCommitments,
    pinned,
    transcriptRepr,
    domainDegree,
  };
}
