/**
 * Circuit synthesis as halo2_proofs 0.3 runs it: `SimpleFloorPlanner`'s
 * single-pass layouter (each region is measured by a first run of its closure,
 * then placed at the first row where none of its columns, selectors included,
 * is in use), constants in the first constants column, table columns filled
 * with their first value, over an {@link Assignment} that is either the
 * keygen assembly (fixed values, selectors, copies) or the prover's witness
 * collection (advice values).
 *
 * A value is a field element, or `undefined` where it is unknown (keygen).
 */
import { Fp } from "../field.js";
import type { Column, Selector } from "./expression.js";
import type { TableColumn } from "./constraint-system.js";

export type Value = bigint | undefined;

/** `Value::map`. */
export const vmap = <T>(v: T | undefined, f: (x: T) => bigint): Value =>
  v === undefined ? undefined : f(v);

/** `Value::zip` then map. */
export function vzip(values: Value[], f: (...xs: bigint[]) => bigint): Value {
  if (values.some((v) => v === undefined)) return undefined;
  return f(...(values as bigint[]));
}

export interface Cell {
  readonly region: number;
  readonly row: number;
  readonly column: Column;
}

/** The backend a synthesis writes into. */
export interface Assignment {
  enableSelector(selector: Selector, row: number): void;
  queryInstance(column: Column<"Instance">, row: number): Value;
  assignAdvice(column: Column<"Advice">, row: number, value: () => Value): void;
  assignFixed(column: Column<"Fixed">, row: number, value: () => Value): void;
  copy(left: Column, leftRow: number, right: Column, rightRow: number): void;
  fillFromRow(column: Column<"Fixed">, row: number, value: Value): void;
}

export class AssignedCell {
  constructor(
    readonly cell: Cell,
    readonly value: Value,
  ) {}

  /** Copy this cell's value into `column` at `offset` and constrain them equal. */
  copyAdvice(
    region: Region,
    column: Column<"Advice">,
    offset: number,
  ): AssignedCell {
    const copied = region.assignAdvice(column, offset, () => this.value);
    region.constrainEqual(copied.cell, this.cell);
    return copied;
  }
}

const key = (c: Column): string => `${c.type}:${c.index}`;
const selectorKey = (s: Selector): string => `Selector:${s.index}`;

interface RegionBackend {
  enableSelector(s: Selector, offset: number): void;
  assignAdvice(c: Column<"Advice">, offset: number, v: () => Value): void;
  assignFixed(c: Column<"Fixed">, offset: number, v: () => Value): void;
  queryInstance(c: Column<"Instance">, row: number): Value;
  copyFromInstance(cell: Cell, instance: Column<"Instance">, row: number): void;
  constrainConstant(cell: Cell, constant: bigint): void;
  constrainEqual(a: Cell, b: Cell): void;
}

/** A region as its closure sees it, in either the measuring or the assigning pass. */
export class Region {
  constructor(
    private readonly index: number,
    private readonly backend: RegionBackend,
  ) {}

  enableSelector(selector: Selector, offset: number): void {
    this.backend.enableSelector(selector, offset);
  }

  assignAdvice(
    column: Column<"Advice">,
    offset: number,
    value: () => Value,
  ): AssignedCell {
    // As in the reference, the cell's value is known only where the backend
    // evaluated it: never in the measuring pass or at key generation.
    let seen: Value;
    this.backend.assignAdvice(column, offset, () => {
      seen = value();
      return seen;
    });
    return new AssignedCell({ region: this.index, row: offset, column }, seen);
  }

  assignAdviceFromConstant(
    column: Column<"Advice">,
    offset: number,
    constant: bigint,
  ): AssignedCell {
    const cell = this.assignAdvice(column, offset, () => constant);
    this.backend.constrainConstant(cell.cell, constant);
    // A constant's value is known in every pass.
    return new AssignedCell(cell.cell, constant);
  }

  assignAdviceFromInstance(
    instance: Column<"Instance">,
    row: number,
    column: Column<"Advice">,
    offset: number,
  ): AssignedCell {
    const value = this.backend.queryInstance(instance, row);
    const cell = this.assignAdvice(column, offset, () => value);
    this.backend.copyFromInstance(cell.cell, instance, row);
    return cell;
  }

  assignFixed(
    column: Column<"Fixed">,
    offset: number,
    value: Value,
  ): AssignedCell {
    let seen: Value;
    this.backend.assignFixed(column, offset, () => {
      seen = value;
      return seen;
    });
    return new AssignedCell({ region: this.index, row: offset, column }, seen);
  }

  constrainConstant(cell: Cell, constant: bigint): void {
    this.backend.constrainConstant(cell, constant);
  }

  constrainEqual(a: Cell, b: Cell): void {
    this.backend.constrainEqual(a, b);
  }
}

/** A lookup table as its closure sees it. */
export interface Table {
  assignCell(column: TableColumn, offset: number, value: Value): void;
}

/** `SimpleFloorPlanner` over an {@link Assignment}. */
export class Layouter {
  private readonly regionStarts: number[] = [];
  private readonly heights = new Map<string, number>();
  private readonly tableColumns: TableColumn[] = [];

  constructor(
    private readonly cs: Assignment,
    private readonly constants: Column<"Fixed">[],
  ) {}

  /** `Layouter::namespace`: names only, no effect on the layout. */
  namespace(): Layouter {
    return this;
  }

  private absolute(cell: Cell): number {
    return this.regionStarts[cell.region] + cell.row;
  }

  assignRegion<T>(assignment: (region: Region) => T): T {
    const index = this.regionStarts.length;

    // Measuring pass: the columns and selectors the region touches, and its height.
    const used = new Set<string>();
    let rowCount = 0;
    const grow = (offset: number) =>
      (rowCount = Math.max(rowCount, offset + 1));
    assignment(
      new Region(index, {
        enableSelector: (s, o) => (used.add(selectorKey(s)), grow(o)),
        assignAdvice: (c, o) => (used.add(key(c)), grow(o)),
        assignFixed: (c, o) => (used.add(key(c)), grow(o)),
        queryInstance: () => undefined,
        copyFromInstance: () => undefined,
        constrainConstant: () => undefined,
        constrainEqual: () => undefined,
      }),
    );

    let start = 0;
    for (const c of used) start = Math.max(start, this.heights.get(c) ?? 0);
    this.regionStarts.push(start);
    for (const c of used) this.heights.set(c, start + rowCount);

    // Assigning pass.
    const constants: [bigint, Cell][] = [];
    const result = assignment(
      new Region(index, {
        enableSelector: (s, o) => this.cs.enableSelector(s, start + o),
        assignAdvice: (c, o, v) => this.cs.assignAdvice(c, start + o, v),
        assignFixed: (c, o, v) => this.cs.assignFixed(c, start + o, v),
        queryInstance: (c, row) => this.cs.queryInstance(c, row),
        copyFromInstance: (cell, instance, row) =>
          this.cs.copy(cell.column, this.absolute(cell), instance, row),
        constrainConstant: (cell, constant) => constants.push([constant, cell]),
        constrainEqual: (a, b) =>
          this.cs.copy(a.column, this.absolute(a), b.column, this.absolute(b)),
      }),
    );

    if (this.constants.length === 0) {
      if (constants.length) throw new Error("not enough columns for constants");
    } else {
      const column = this.constants[0];
      let next = this.heights.get(key(column)) ?? 0;
      for (const [value, cell] of constants) {
        const row = next;
        this.cs.assignFixed(column, row, () => value);
        this.cs.copy(column, row, cell.column, this.absolute(cell));
        next += 1;
      }
      this.heights.set(key(column), next);
    }
    return result;
  }

  assignTable(assignment: (table: Table) => void): void {
    const tables = new Map<
      TableColumn,
      { defaultValue: Value | null; assigned: boolean[] }
    >();
    assignment({
      assignCell: (column, offset, value) => {
        if (this.tableColumns.includes(column))
          throw new Error("table column already used");
        let entry = tables.get(column);
        if (!entry) {
          entry = { defaultValue: null, assigned: [] };
          tables.set(column, entry);
        }
        this.cs.assignFixed(column.inner, offset, () => value);
        if (offset === 0) {
          if (entry.defaultValue !== null)
            throw new Error("table default overwritten");
          entry.defaultValue = value;
        }
        while (entry.assigned.length <= offset) entry.assigned.push(false);
        entry.assigned[offset] = true;
      },
    });
    let length = 0;
    for (const entry of tables.values()) {
      if (entry.defaultValue === null || !entry.assigned.every((b) => b))
        throw new Error("table column not fully assigned");
      if (length !== 0 && length !== entry.assigned.length)
        throw new Error("uneven table column lengths");
      length = entry.assigned.length;
    }
    for (const [column, entry] of tables) {
      this.tableColumns.push(column);
      this.cs.fillFromRow(column.inner, length, entry.defaultValue as Value);
    }
  }

  constrainInstance(
    cell: Cell,
    instance: Column<"Instance">,
    row: number,
  ): void {
    this.cs.copy(cell.column, this.absolute(cell), instance, row);
  }
}

/** Reduce a value into the field, keeping unknown values unknown. */
export const vfield = (v: Value): Value => (v === undefined ? v : Fp.mod(v));
