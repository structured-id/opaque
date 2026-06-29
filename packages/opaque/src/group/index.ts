/**
 * Group operations registry.
 *
 * Maps CurveId → GroupOps implementation.
 * Lazily instantiates NIST curves via createWeierstrassGroup factory.
 */
import { p256, p256_hasher, p384, p384_hasher, p521, p521_hasher } from '@noble/curves/nist.js';
import { CurveId } from '../suites.js';
import type { GroupOps } from './types.js';
import { ristretto255Group } from './ristretto255.js';
import { createWeierstrassGroup } from './weierstrass.js';

export type { GroupElement, GroupOps } from './types.js';

// ── NIST curve instances (lazy) ──

let _p256Group: GroupOps | undefined;
let _p384Group: GroupOps | undefined;
let _p521Group: GroupOps | undefined;

function getP256Group(): GroupOps {
  if (!_p256Group) {
    _p256Group = createWeierstrassGroup(p256 as never, p256_hasher as never, 32, 33);
  }
  return _p256Group;
}

function getP384Group(): GroupOps {
  if (!_p384Group) {
    _p384Group = createWeierstrassGroup(p384 as never, p384_hasher as never, 48, 49);
  }
  return _p384Group;
}

function getP521Group(): GroupOps {
  if (!_p521Group) {
    _p521Group = createWeierstrassGroup(p521 as never, p521_hasher as never, 66, 67);
  }
  return _p521Group;
}

/** Get GroupOps for a given curve. */
export function getGroup(curve: CurveId): GroupOps {
  switch (curve) {
    case CurveId.RISTRETTO255:
      return ristretto255Group;
    case CurveId.P256:
      return getP256Group();
    case CurveId.P384:
      return getP384Group();
    case CurveId.P521:
      return getP521Group();
    default:
      throw new Error(`Unsupported curve: ${curve}`);
  }
}
