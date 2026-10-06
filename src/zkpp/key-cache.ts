/**
 * The stored forms of the commitment key and of a shape's column
 * commitments. Points are kept uncompressed (x ‖ y, 32 bytes little-endian
 * each) so loading needs no square roots; every point is checked to lie on
 * Vesta, and anything that does not decode exactly is treated as absent, so a
 * damaged entry is derived again rather than used.
 */
import { blake2b } from "@noble/hashes/blake2.js";
import { Vesta, type Point } from "../curve.js";
import { FQ_MODULUS } from "../field.js";
import type { KeygenColumns, Srs } from "../halo2/keygen.js";

type Affine = NonNullable<Point>;

/** Bumped when a stored layout changes; old entries then stop matching. */
const FORMAT = 1;

const le32 = (v: bigint, out: Uint8Array, at: number) => {
  for (let i = 0; i < 32; i++)
    out[at + i] = Number((v >> BigInt(8 * i)) & 0xffn);
};
const readLe32 = (b: Uint8Array, at: number): bigint => {
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(b[at + i]);
  return v;
};

function encodePoints(header: Uint8Array, points: Affine[]): Uint8Array {
  const out = new Uint8Array(header.length + 4 + points.length * 64);
  out.set(header);
  new DataView(out.buffer).setUint32(header.length, points.length, true);
  let at = header.length + 4;
  for (const p of points) {
    le32(p.x, out, at);
    le32(p.y, out, at + 32);
    at += 64;
  }
  return out;
}

function decodePoints(
  bytes: Uint8Array,
  header: Uint8Array,
  count: number,
): Affine[] | null {
  if (bytes.length !== header.length + 4 + count * 64) return null;
  for (let i = 0; i < header.length; i++)
    if (bytes[i] !== header[i]) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(header.length, true) !== count) return null;
  const out: Affine[] = [];
  for (let i = 0, at = header.length + 4; i < count; i++, at += 64) {
    const p = { x: readLe32(bytes, at), y: readLe32(bytes, at + 32) };
    // Canonical coordinates only: x + q would pass the curve equation mod q.
    if (p.x >= FQ_MODULUS || p.y >= FQ_MODULUS || !Vesta.isOnCurve(p))
      return null;
    out.push(p);
  }
  return out;
}

const srsHeader = (k: number) => Uint8Array.of(FORMAT, 0x53, k);

/** The stored commitment key: g, its Lagrange basis, w and u. */
export function encodeSrs(srs: Srs): Uint8Array {
  return encodePoints(srsHeader(srs.k), [
    ...srs.g,
    ...srs.gLagrange,
    srs.w,
    srs.u,
  ]);
}

export function decodeSrs(bytes: Uint8Array, k: number): Srs | null {
  const n = 1 << k;
  const pts = decodePoints(bytes, srsHeader(k), 2 * n + 2);
  if (!pts) return null;
  return {
    k,
    g: pts.slice(0, n),
    gLagrange: pts.slice(n, 2 * n),
    w: pts[2 * n],
    u: pts[2 * n + 1],
  };
}

/**
 * What a shape's commitments are a function of: the domain size, the
 * constraint system and every fixed and sigma value. Equal digests mean the
 * stored commitments are this circuit's, whatever version wrote them.
 */
export function columnsDigest(columns: KeygenColumns): Uint8Array {
  const h = blake2b.create({ dkLen: 32 });
  const enc = new TextEncoder();
  h.update(Uint8Array.of(FORMAT, columns.k));
  h.update(enc.encode(columns.cs.pinnedDebug()));
  const buf = new Uint8Array(32);
  for (const col of [...columns.fixed, ...columns.sigmas]) {
    for (const v of col) {
      le32(v, buf, 0);
      h.update(buf);
    }
  }
  return h.digest();
}

/** The stored commitments of one shape, headed by its columns' digest. */
export function encodeCommitments(
  digest: Uint8Array,
  points: Affine[],
): Uint8Array {
  return encodePoints(Uint8Array.of(FORMAT, 0x43, ...digest), points);
}

/** The commitments, or null when the entry is for other columns or damaged. */
export function decodeCommitments(
  bytes: Uint8Array,
  digest: Uint8Array,
  count: number,
): Affine[] | null {
  return decodePoints(bytes, Uint8Array.of(FORMAT, 0x43, ...digest), count);
}
