/** Assigned curve points of the ECC chip (`EccPoint`, `NonIdentityEccPoint`). */
import type { Point } from "../../curve.js";
import type { AssignedCell } from "../../halo2/layouter.js";

/** A point in affine coordinates, the identity as (0, 0). */
export class EccPoint {
  constructor(
    readonly x: AssignedCell,
    readonly y: AssignedCell,
  ) {}

  /** The point, if known. */
  point(): Point | undefined {
    const { value: x } = this.x;
    const { value: y } = this.y;
    if (x === undefined || y === undefined) return undefined;
    return x === 0n && y === 0n ? null : { x, y };
  }
}

/** A point known not to be the identity. */
export class NonIdentityEccPoint extends EccPoint {
  point(): Point | undefined {
    const p = super.point();
    if (p === null) throw new Error("non-identity point is the identity");
    return p;
  }
}
