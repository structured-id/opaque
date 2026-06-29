/**
 * Generic Weierstrass curve group operations for NIST curves.
 *
 * Factory that creates GroupOps from @noble/curves Weierstrass curve + hasher.
 * Used for P-256, P-384, P-521.
 */
import { randomBytes } from '@noble/hashes/utils.js';
import type { GroupElement, GroupOps } from './types.js';

/** Minimal interface for @noble/curves Weierstrass curve. */
interface WeierstrassCurve {
  keygen(): { secretKey: Uint8Array; publicKey: Uint8Array };
  getSharedSecret(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  Point: {
    BASE: WeierstrassPoint;
    ZERO: WeierstrassPoint;
    Fn: { ORDER: bigint; inv(n: bigint): bigint; create(n: bigint): bigint };
    fromBytes(bytes: Uint8Array): WeierstrassPoint;
  };
}

/** Minimal interface for @noble/curves hash-to-curve hasher. */
interface WeierstrassHasher {
  hashToCurve(input: Uint8Array, opts: { DST: Uint8Array }): WeierstrassPoint;
}

interface WeierstrassPoint {
  multiply(scalar: bigint): WeierstrassPoint;
  add(other: WeierstrassPoint): WeierstrassPoint;
  toBytes(compressed: boolean): Uint8Array;
  is0(): boolean;
  toAffine(): { x: bigint; y: bigint };
}

function wrap(point: WeierstrassPoint): GroupElement {
  return { _point: point };
}

function unwrap(el: GroupElement): WeierstrassPoint {
  return el._point as WeierstrassPoint;
}

/** Convert bigint to fixed-size big-endian bytes. */
function bigintToBytes(n: bigint, size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  let val = n;
  for (let i = size - 1; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

/** Convert big-endian bytes to bigint. */
function bytesToBigint(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

/** Create GroupOps for a Weierstrass curve. */
export function createWeierstrassGroup(
  curve: WeierstrassCurve,
  hasher: WeierstrassHasher,
  scalarSize: number,
  elementSize: number,
): GroupOps {
  const Fn = curve.Point.Fn;

  return {
    scalarSize,
    elementSize,

    hashToGroup(input: Uint8Array, dst: Uint8Array): GroupElement {
      return wrap(hasher.hashToCurve(input, { DST: dst }));
    },

    randomScalar(): Uint8Array {
      // Generate uniform random scalar in [1, order)
      // Use extra bytes (2x scalar size) to avoid bias via modular reduction
      const raw = randomBytes(scalarSize * 2);
      const n = bytesToBigint(raw);
      const reduced = Fn.create(n);
      // Ensure non-zero
      const scalar = reduced === 0n ? 1n : reduced;
      return bigintToBytes(scalar, scalarSize);
    },

    scalarMult(scalar: Uint8Array, element: GroupElement): GroupElement {
      const s = bytesToBigint(scalar);
      return wrap(unwrap(element).multiply(s));
    },

    scalarInverse(scalar: Uint8Array): Uint8Array {
      const s = bytesToBigint(scalar);
      const inv = Fn.inv(s);
      return bigintToBytes(inv, scalarSize);
    },

    serializeElement(element: GroupElement): Uint8Array {
      return unwrap(element).toBytes(true);
    },

    deserializeElement(bytes: Uint8Array): GroupElement {
      return wrap(curve.Point.fromBytes(bytes));
    },

    generateKeypair(): { secretKey: Uint8Array; publicKey: Uint8Array } {
      return curve.keygen();
    },

    ecdh(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
      return curve.getSharedSecret(secretKey, publicKey);
    },

    identity(): GroupElement {
      return wrap(curve.Point.ZERO);
    },

    add(a: GroupElement, b: GroupElement): GroupElement {
      return wrap(unwrap(a).add(unwrap(b)));
    },

    scalarBaseMult(scalar: Uint8Array): GroupElement {
      const s = Fn.create(bytesToBigint(scalar));
      const nonZero = s === 0n ? 1n : s;
      return wrap(curve.Point.BASE.multiply(nonZero));
    },

    scalarReduce(bytes: Uint8Array): Uint8Array {
      const n = bytesToBigint(bytes);
      const reduced = Fn.create(n);
      const nonZero = reduced === 0n ? 1n : reduced;
      return bigintToBytes(nonZero, scalarSize);
    },
  };
}
