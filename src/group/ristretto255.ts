/**
 * Ristretto255 group operations via @noble/curves.
 *
 * RFC 9807 primary suite: ristretto255 + SHA-512.
 */
import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';
import type { GroupElement, GroupOps } from './types.js';

const Point = ristretto255.Point;
const Fn = Point.Fn;

type RistrettoPoint = typeof Point.BASE;

function wrap(point: RistrettoPoint): GroupElement {
  return { _point: point };
}

function unwrap(el: GroupElement): RistrettoPoint {
  return el._point as RistrettoPoint;
}

function bigintToBytes(n: bigint, size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  let val = n;
  for (let i = size - 1; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

function bytesToBigint(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

export const ristretto255Group: GroupOps = {
  scalarSize: 32,
  elementSize: 32,

  hashToGroup(input: Uint8Array, dst: Uint8Array): GroupElement {
    return wrap(ristretto255_hasher.hashToCurve(input, { DST: dst }) as RistrettoPoint);
  },

  randomScalar(): Uint8Array {
    const raw = randomBytes(64);
    const n = bytesToBigint(raw);
    const reduced = Fn.create(n);
    const scalar = reduced === 0n ? 1n : reduced;
    return bigintToBytes(scalar, 32);
  },

  scalarMult(scalar: Uint8Array, element: GroupElement): GroupElement {
    const s = bytesToBigint(scalar);
    return wrap(unwrap(element).multiply(s));
  },

  scalarInverse(scalar: Uint8Array): Uint8Array {
    const s = bytesToBigint(scalar);
    const inv = Fn.inv(s);
    return bigintToBytes(inv, 32);
  },

  serializeElement(element: GroupElement): Uint8Array {
    return unwrap(element).toBytes();
  },

  deserializeElement(bytes: Uint8Array): GroupElement {
    return wrap(Point.fromBytes(bytes) as RistrettoPoint);
  },

  generateKeypair(): { secretKey: Uint8Array; publicKey: Uint8Array } {
    const secretKey = this.randomScalar();
    const s = bytesToBigint(secretKey);
    const publicKey = Point.BASE.multiply(s).toBytes();
    return { secretKey, publicKey };
  },

  ecdh(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    const point = Point.fromBytes(publicKey) as RistrettoPoint;
    const s = bytesToBigint(secretKey);
    return point.multiply(s).toBytes();
  },

  identity(): GroupElement {
    return wrap(Point.ZERO as RistrettoPoint);
  },

  add(a: GroupElement, b: GroupElement): GroupElement {
    return wrap(unwrap(a).add(unwrap(b)));
  },

  scalarBaseMult(scalar: Uint8Array): GroupElement {
    const s = Fn.create(bytesToBigint(scalar));
    const nonZero = s === 0n ? 1n : s;
    return wrap(Point.BASE.multiply(nonZero));
  },

  scalarReduce(bytes: Uint8Array): Uint8Array {
    const n = bytesToBigint(bytes);
    const reduced = Fn.create(n);
    const nonZero = reduced === 0n ? 1n : reduced;
    return bigintToBytes(nonZero, 32);
  },
};
