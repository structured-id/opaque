/**
 * The constraint system of halo2_proofs 0.3 (`plonk::ConstraintSystem`): the
 * column, query, gate, lookup and permutation bookkeeping a circuit's
 * `configure` builds, selector compression, and the pinned Debug text the
 * verifying key hashes. Every index is allocated in the reference's order, so
 * a configure ported call for call yields the same system.
 */
import {
  add,
  columnDebug,
  constant,
  degree,
  evaluate,
  expressionDebug,
  extractSimpleSelector,
  containsSimpleSelector,
  mul,
  neg,
  rotationDebug,
  scale,
  sub,
  type Column,
  type ColumnType,
  type Expression,
  type Selector,
} from "./expression.js";

export interface TableColumn {
  readonly inner: Column<"Fixed">;
}

export interface Gate {
  readonly name: string;
  polys: Expression[];
}

export interface LookupArgument {
  inputExpressions: Expression[];
  tableExpressions: Expression[];
}

const sameColumn = (a: Column, b: Column): boolean =>
  a.index === b.index && a.type === b.type;

/** Queries available while building a gate or a lookup. */
export class VirtualCells {
  constructor(private readonly cs: ConstraintSystem) {}

  querySelector(s: Selector): Expression {
    return { k: "selector", s };
  }

  queryFixed(column: Column<"Fixed">): Expression {
    return {
      k: "fixed",
      q: {
        index: this.cs.queryFixedIndex(column),
        column: column.index,
        rotation: 0,
      },
    };
  }

  queryAdvice(column: Column<"Advice">, rotation = 0): Expression {
    return {
      k: "advice",
      q: {
        index: this.cs.queryAdviceIndex(column, rotation),
        column: column.index,
        rotation,
      },
    };
  }

  queryInstance(column: Column<"Instance">, rotation = 0): Expression {
    return {
      k: "instance",
      q: {
        index: this.cs.queryInstanceIndex(column, rotation),
        column: column.index,
        rotation,
      },
    };
  }

  queryAny(column: Column, rotation = 0): Expression {
    switch (column.type) {
      case "Advice":
        return this.queryAdvice(column as Column<"Advice">, rotation);
      case "Fixed":
        if (rotation !== 0)
          throw new Error(
            "Fixed columns can only be queried at the current rotation",
          );
        return this.queryFixed(column as Column<"Fixed">);
      case "Instance":
        return this.queryInstance(column as Column<"Instance">, rotation);
    }
  }
}

export class ConstraintSystem {
  numFixed = 0;
  numAdvice = 0;
  numInstance = 0;
  numSelectors = 0;
  gates: Gate[] = [];
  adviceQueries: [Column<"Advice">, number][] = [];
  numAdviceQueries: number[] = [];
  instanceQueries: [Column<"Instance">, number][] = [];
  fixedQueries: [Column<"Fixed">, number][] = [];
  /** Columns of the permutation argument, in `enable_equality` order. */
  permutation: Column[] = [];
  lookups: LookupArgument[] = [];
  constants: Column<"Fixed">[] = [];
  minimumDegree: number | null = null;

  fixedColumn(): Column<"Fixed"> {
    return { index: this.numFixed++, type: "Fixed" };
  }

  adviceColumn(): Column<"Advice"> {
    this.numAdviceQueries.push(0);
    return { index: this.numAdvice++, type: "Advice" };
  }

  instanceColumn(): Column<"Instance"> {
    return { index: this.numInstance++, type: "Instance" };
  }

  lookupTableColumn(): TableColumn {
    return { inner: this.fixedColumn() };
  }

  selector(): Selector {
    return { index: this.numSelectors++, simple: true };
  }

  complexSelector(): Selector {
    return { index: this.numSelectors++, simple: false };
  }

  queryFixedIndex(column: Column<"Fixed">): number {
    const found = this.fixedQueries.findIndex(
      ([c, r]) => c.index === column.index && r === 0,
    );
    if (found >= 0) return found;
    this.fixedQueries.push([column, 0]);
    return this.fixedQueries.length - 1;
  }

  queryAdviceIndex(column: Column<"Advice">, rotation: number): number {
    const found = this.adviceQueries.findIndex(
      ([c, r]) => c.index === column.index && r === rotation,
    );
    if (found >= 0) return found;
    this.adviceQueries.push([column, rotation]);
    this.numAdviceQueries[column.index] += 1;
    return this.adviceQueries.length - 1;
  }

  queryInstanceIndex(column: Column<"Instance">, rotation: number): number {
    const found = this.instanceQueries.findIndex(
      ([c, r]) => c.index === column.index && r === rotation,
    );
    if (found >= 0) return found;
    this.instanceQueries.push([column, rotation]);
    return this.instanceQueries.length - 1;
  }

  private queryAnyIndex(column: Column, rotation: number): number {
    switch (column.type) {
      case "Advice":
        return this.queryAdviceIndex(column as Column<"Advice">, rotation);
      case "Fixed":
        return this.queryFixedIndex(column as Column<"Fixed">);
      case "Instance":
        return this.queryInstanceIndex(column as Column<"Instance">, rotation);
    }
  }

  /** The index of an existing query; used by the prover. */
  queryIndexOf(type: ColumnType, column: number, rotation: number): number {
    const list =
      type === "Advice"
        ? this.adviceQueries
        : type === "Fixed"
          ? this.fixedQueries
          : this.instanceQueries;
    const i = list.findIndex(([c, r]) => c.index === column && r === rotation);
    if (i < 0) throw new Error(`no ${type} query for column ${column}`);
    return i;
  }

  enableEquality(column: Column): void {
    this.queryAnyIndex(column, 0);
    if (!this.permutation.some((c) => sameColumn(c, column)))
      this.permutation.push(column);
  }

  enableConstant(column: Column<"Fixed">): void {
    if (!this.constants.some((c) => c.index === column.index)) {
      this.constants.push(column);
      this.enableEquality(column);
    }
  }

  createGate(
    name: string,
    constraints: (meta: VirtualCells) => Expression[],
  ): void {
    const polys = constraints(new VirtualCells(this));
    if (polys.length === 0)
      throw new Error("Gates must contain at least one constraint.");
    this.gates.push({ name, polys });
  }

  lookup(
    tableMap: (meta: VirtualCells) => [Expression, TableColumn][],
  ): number {
    const cells = new VirtualCells(this);
    const map = tableMap(cells).map(
      ([input, table]): [Expression, Expression] => {
        if (containsSimpleSelector(input))
          throw new Error(
            "expression containing simple selector supplied to lookup argument",
          );
        return [input, cells.queryFixed(table.inner)];
      },
    );
    this.lookups.push({
      inputExpressions: map.map(([i]) => i),
      tableExpressions: map.map(([, t]) => t),
    });
    return this.lookups.length - 1;
  }

  degree(): number {
    let d = 3; // the permutation argument
    let lookupDegree = 1;
    for (const l of this.lookups) {
      let input = 1;
      for (const e of l.inputExpressions) input = Math.max(input, degree(e));
      let table = 1;
      for (const e of l.tableExpressions) table = Math.max(table, degree(e));
      lookupDegree = Math.max(lookupDegree, Math.max(4, 2 + input + table));
    }
    d = Math.max(d, lookupDegree);
    let gateDegree = 0;
    for (const g of this.gates)
      for (const p of g.polys) gateDegree = Math.max(gateDegree, degree(p));
    d = Math.max(d, gateDegree);
    return Math.max(d, this.minimumDegree ?? 1);
  }

  blindingFactors(): number {
    const factors = Math.max(3, Math.max(1, ...this.numAdviceQueries));
    return factors + 1 + 1;
  }

  minimumRows(): number {
    return this.blindingFactors() + 3;
  }

  /**
   * Replace the selectors by fixed columns (halo2 `compress_selectors`):
   * complex selectors each get a 0/1 column, simple ones are packed into
   * shared columns as far as the degree allows. Returns the new columns'
   * values, appended after the existing fixed columns.
   */
  compressSelectors(activations: boolean[][]): bigint[][] {
    if (activations.length !== this.numSelectors)
      throw new Error("selector assignments do not match the selector count");
    const degrees = new Array<number>(activations.length).fill(0);
    for (const g of this.gates)
      for (const p of g.polys) {
        const s = extractSimpleSelector(p);
        if (s) degrees[s.index] = Math.max(degrees[s.index], degree(p));
      }
    const maxDegree = this.degree();
    const n = activations.length ? activations[0].length : 0;

    const columns: bigint[][] = [];
    const replacement: Expression[] = new Array(activations.length);
    const allocate = (): Expression => {
      const column = this.fixedColumn();
      return {
        k: "fixed",
        q: {
          index: this.queryFixedIndex(column),
          column: column.index,
          rotation: 0,
        },
      };
    };

    // Complex selectors, and selectors in no gate, get a column each.
    const simple: number[] = [];
    for (let i = 0; i < activations.length; i++) {
      if (degrees[i] === 0) {
        replacement[i] = allocate();
        columns.push(activations[i].map((b) => (b ? 1n : 0n)));
      } else simple.push(i);
    }

    // Exclusion: two selectors conflict when both are enabled on some row.
    const conflicts = (a: number, b: number): boolean => {
      const x = activations[a];
      const y = activations[b];
      for (let r = 0; r < n; r++) if (x[r] && y[r]) return true;
      return false;
    };
    const excluded = simple.map((si, i) =>
      simple.slice(0, i).map((sj) => conflicts(si, sj)),
    );
    const added = new Array<boolean>(simple.length).fill(false);

    for (let i = 0; i < simple.length; i++) {
      if (added[i]) continue;
      added[i] = true;
      let d = degrees[simple[i]] - 1;
      const combination = [i];
      for (let j = i + 1; j < simple.length; j++) {
        if (d + combination.length === maxDegree) break;
        if (added[j]) continue;
        if (combination.some((c) => excluded[j][c])) continue;
        const newD = Math.max(d, degrees[simple[j]] - 1);
        if (newD + combination.length + 1 > maxDegree) continue;
        d = newD;
        combination.push(j);
        added[j] = true;
      }

      const assignment = new Array<bigint>(n).fill(0n);
      const query = allocate();
      let assignedRoot = 1n;
      for (const c of combination) {
        let expression = query;
        let root = 1n;
        for (let t = 0; t < combination.length; t++) {
          if (root !== assignedRoot)
            expression = mul(expression, sub(constant(root), query));
          root += 1n;
        }
        const acts = activations[simple[c]];
        for (let r = 0; r < n; r++) if (acts[r]) assignment[r] = assignedRoot;
        assignedRoot += 1n;
        replacement[simple[c]] = expression;
      }
      columns.push(assignment);
    }

    const replace = (e: Expression, mustBeComplex: boolean): Expression =>
      evaluate<Expression>(e, {
        constant: (v) => constant(v),
        selector: (s) => {
          if (mustBeComplex && s.simple)
            throw new Error("simple selector in a lookup argument");
          return replacement[s.index];
        },
        fixed: (q) => ({ k: "fixed", q }),
        advice: (q) => ({ k: "advice", q }),
        instance: (q) => ({ k: "instance", q }),
        negated: (a) => neg(a),
        sum: (a, b) => add(a, b),
        product: (a, b) => mul(a, b),
        scaled: (a, f) => scale(a, f),
      });
    for (const g of this.gates) g.polys = g.polys.map((p) => replace(p, false));
    for (const l of this.lookups) {
      l.inputExpressions = l.inputExpressions.map((e) => replace(e, true));
      l.tableExpressions = l.tableExpressions.map((e) => replace(e, true));
    }
    return columns;
  }

  /** Rust `{:?}` of `PinnedConstraintSystem`. */
  pinnedDebug(): string {
    const list = <T>(xs: T[], f: (x: T) => string): string =>
      `[${xs.map(f).join(", ")}]`;
    const query = ([c, r]: [Column, number]): string =>
      `(${columnDebug(c)}, ${rotationDebug(r)})`;
    const gates = this.gates.flatMap((g) => g.polys);
    return (
      "PinnedConstraintSystem { " +
      `num_fixed_columns: ${this.numFixed}, ` +
      `num_advice_columns: ${this.numAdvice}, ` +
      `num_instance_columns: ${this.numInstance}, ` +
      `num_selectors: ${this.numSelectors}, ` +
      `gates: ${list(gates, expressionDebug)}, ` +
      `advice_queries: ${list(this.adviceQueries, query)}, ` +
      `instance_queries: ${list(this.instanceQueries, query)}, ` +
      `fixed_queries: ${list(this.fixedQueries, query)}, ` +
      `permutation: Argument { columns: ${list(this.permutation, columnDebug)} }, ` +
      `lookups: ${list(
        this.lookups,
        (l) =>
          `Argument { input_expressions: ${list(l.inputExpressions, expressionDebug)}, ` +
          `table_expressions: ${list(l.tableExpressions, expressionDebug)} }`,
      )}, ` +
      `constants: ${list(this.constants, columnDebug)}, ` +
      `minimum_degree: ${this.minimumDegree === null ? "None" : `Some(${this.minimumDegree})`} }`
    );
  }
}
