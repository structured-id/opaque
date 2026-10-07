/**
 * The IPA commitment key of halo2_proofs 0.3 (`Params::new(k)`) over Vesta:
 * generators from pasta_curves' hash-to-curve with the "Halo2-Parameters"
 * domain, their Lagrange basis by an inverse FFT over the group, and the
 * blinding and inner-product generators. Deterministic: every client derives
 * the same key.
 */
import { blake2b } from "@noble/hashes/blake2.js";
import { Field as NobleField } from "@noble/curves/abstract/modular.js";
import { Fp, Fq, FQ_MODULUS } from "../field.js";
import { Vesta, type Point } from "../curve.js";
import { omegaForSize } from "../fft.js";
import type { Srs } from "./keygen.js";

type Affine = NonNullable<Point>;

const NFq = NobleField(FQ_MODULUS);

/** 256-bit value from four little-endian 64-bit limbs (`from_raw`). */
const raw = (l: bigint[]): bigint =>
  l[0] | (l[1] << 64n) | (l[2] << 128n) | (l[3] << 192n);

/** Iso-Vesta: y² = x³ + A·x + B, 3-isogenous to Vesta. */
const ISO_A = raw([
  0xc515ad7242eaa6b1n,
  0x9673928c7d01b212n,
  0x81639c4d96f78773n,
  0x267f9b2ee592271an,
]);
const ISO_B = 1265n;
/** SSWU Z = -13. */
const Z = Fq.neg(13n);

/** `Eq::ISOGENY_CONSTANTS`. */
const ISO = [
  [
    0x43cd42c800000001n,
    0x0205dd51cfa0961an,
    0x8e38e38e38e38e39n,
    0x38e38e38e38e38e3n,
  ],
  [
    0x8b95c6aaf703bcc5n,
    0x216b8861ec72bd5dn,
    0xacecf10f5f7c09a2n,
    0x1d935247b4473d17n,
  ],
  [
    0xaeac67bbeb586a3dn,
    0xd59d03d23b39cb11n,
    0xed7ee4a9cdf78f8fn,
    0x18760c7f7a9ad20dn,
  ],
  [
    0xfb539a6f0000002bn,
    0xe1c521a795ac8356n,
    0x1c71c71c71c71c71n,
    0x31c71c71c71c71c7n,
  ],
  [
    0xb7284f7eaf21a2e9n,
    0xa3ad678129b604d3n,
    0x1454798a5b5c56b2n,
    0x0a2de485568125d5n,
  ],
  [
    0xf169c187d2533465n,
    0x30cd6d53df49d235n,
    0x0c621de8b91c242an,
    0x14735171ee542778n,
  ],
  [
    0x6bef1642aaaaaaabn,
    0x5601f4709a8adcb3n,
    0xda12f684bda12f68n,
    0x12f684bda12f684bn,
  ],
  [
    0x8bee58e5fb81de63n,
    0x21d910aefb03b31dn,
    0xd6767887afbe04d1n,
    0x2ec9a923da239e8bn,
  ],
  [
    0x4986913ab4443034n,
    0x97a3ca5c24e9ea63n,
    0x66d1466e9de10e64n,
    0x19b0d87e16e25788n,
  ],
  [
    0x8f64842c55555533n,
    0x8bc32d36fb21a6a3n,
    0x425ed097b425ed09n,
    0x1ed097b425ed097bn,
  ],
  [
    0x58dfecce86b2745en,
    0x06a767bfc35b5bacn,
    0x9e7eb64f890a820cn,
    0x2f44d6c801c1b8bfn,
  ],
  [
    0xd43d449776f99d2fn,
    0x926847fb9ddd76a1n,
    0x252659ba2b546c7en,
    0x3d59f455cafc7668n,
  ],
  [
    0x8c46eb20fffffde5n,
    0x224698fc0994a8ddn,
    0x0000000000000000n,
    0x4000000000000000n,
  ],
].map(raw);

const isSquare = (v: bigint): boolean =>
  v === 0n || Fq.pow(v, (FQ_MODULUS - 1n) / 2n) === 1n;
const isOdd = (v: bigint): boolean => (Fq.mod(v) & 1n) === 1n;

/** pasta_curves `hash_to_field`: BLAKE2b in XMD form, two field elements. */
function hashToField(
  curveId: string,
  prefix: string,
  message: Uint8Array,
): [bigint, bigint] {
  const enc = new TextEncoder();
  const tag = enc.encode(`${prefix}-${curveId}_XMD:BLAKE2b_SSWU_RO_`);
  const tagLen = Uint8Array.of(22 + curveId.length + prefix.length);
  const h = () =>
    blake2b.create({ dkLen: 64, personalization: new Uint8Array(16) });
  const b0 = h()
    .update(new Uint8Array(128))
    .update(message)
    .update(Uint8Array.of(0, 128, 0))
    .update(tag)
    .update(tagLen)
    .digest();
  const b1 = h()
    .update(b0)
    .update(Uint8Array.of(1))
    .update(tag)
    .update(tagLen)
    .digest();
  const x = b0.map((v, i) => v ^ b1[i]);
  const b2 = h()
    .update(x)
    .update(Uint8Array.of(2))
    .update(tag)
    .update(tagLen)
    .digest();
  const toField = (big: Uint8Array) =>
    Fq.fromUniformBytes(big.slice().reverse());
  return [toField(b1), toField(b2)];
}

/** Simplified SWU onto iso-Vesta, the root's sign matching `u` (RFC 9380 §6.6.2). */
function mapToIso(u: bigint): Affine {
  const zu2 = Fq.mul(Z, Fq.square(u));
  const ta = Fq.add(Fq.square(zu2), zu2);
  const div = Fq.mul(ISO_A, ta === 0n ? Z : Fq.neg(ta));
  const x1 = Fq.mul(Fq.mul(ISO_B, Fq.add(ta, 1n)), Fq.inv(div));
  const g = (x: bigint) =>
    Fq.add(Fq.add(Fq.mul(Fq.square(x), x), Fq.mul(ISO_A, x)), ISO_B);
  let x = x1;
  let gx = g(x1);
  if (!isSquare(gx)) {
    x = Fq.mul(zu2, x1);
    gx = g(x);
  }
  let y = NFq.sqrt(gx);
  if (isOdd(u) !== isOdd(y)) y = Fq.neg(y);
  return { x, y };
}

/** Affine addition on iso-Vesta (a ≠ 0). */
function isoAdd(p: Affine, q: Affine): Affine {
  let lambda: bigint;
  if (p.x === q.x) {
    if (Fq.add(p.y, q.y) === 0n)
      throw new Error("hash-to-curve: identity on the isogenous curve");
    lambda = Fq.mul(
      Fq.add(Fq.mul(3n, Fq.square(p.x)), ISO_A),
      Fq.inv(Fq.mul(2n, p.y)),
    );
  } else lambda = Fq.mul(Fq.sub(q.y, p.y), Fq.inv(Fq.sub(q.x, p.x)));
  const x = Fq.sub(Fq.sub(Fq.square(lambda), p.x), q.x);
  return { x, y: Fq.sub(Fq.mul(lambda, Fq.sub(p.x, x)), p.y) };
}

/** The 3-isogeny from iso-Vesta to Vesta (pasta `iso_map`, affine). */
function isoMap(p: Affine): Affine {
  const { x, y } = p;
  const numX = Fq.add(
    Fq.mul(Fq.add(Fq.mul(Fq.add(Fq.mul(ISO[0], x), ISO[1]), x), ISO[2]), x),
    ISO[3],
  );
  const divX = Fq.add(Fq.mul(Fq.add(x, ISO[4]), x), ISO[5]);
  const numY = Fq.mul(
    Fq.add(
      Fq.mul(Fq.add(Fq.mul(Fq.add(Fq.mul(ISO[6], x), ISO[7]), x), ISO[8]), x),
      ISO[9],
    ),
    y,
  );
  const divY = Fq.add(
    Fq.mul(Fq.add(Fq.mul(Fq.add(x, ISO[10]), x), ISO[11]), x),
    ISO[12],
  );
  return { x: Fq.mul(numX, Fq.inv(divX)), y: Fq.mul(numY, Fq.inv(divY)) };
}

/** `vesta::Point::hash_to_curve(prefix)(message)`. */
export function hashToVesta(prefix: string, message: Uint8Array): Affine {
  const [u0, u1] = hashToField("vesta", prefix, message);
  return isoMap(isoAdd(mapToIso(u0), mapToIso(u1)));
}

/** Generator `i` of the commitment key: hash-to-curve of `0 ‖ i (LE u32)`. */
function generator(i: number): Affine {
  const message = new Uint8Array(5);
  new DataView(message.buffer).setUint32(1, i, true);
  return hashToVesta("Halo2-Parameters", message);
}

/** Generators `start .. start + count` of the commitment key. */
export function generators(start: number, count: number): Affine[] {
  return Array.from({ length: count }, (_, i) => generator(start + i));
}

/** Bit-reversal permutation of `a` (length 2^k), in place. */
function bitReverse(a: Point[]): void {
  const n = a.length;
  for (let i = 0, j = 0; i < n; i++) {
    if (i < j) [a[i], a[j]] = [a[j], a[i]];
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j |= bit;
  }
}

/**
 * The butterflies of one radix-2 stage: `lo + tw·hi` and `lo − tw·hi`,
 * element by element, as two batches.
 */
export function butterflies(
  lo: Point[],
  hi: Point[],
  tw: bigint[],
): [Point[], Point[]] {
  const v = Vesta.mulEach(tw, hi);
  return [Vesta.addEach(lo, v), Vesta.addEach(lo, v.map(Vesta.neg))];
}

/** The butterfly pairs and twiddles of the DIT stage with block size `size`. */
function stageIndices(
  n: number,
  size: number,
  omega: bigint,
): { lo: number[]; hi: number[]; tw: bigint[] } {
  const w = Fp.pow(omega, BigInt(n / size));
  const half = size >> 1;
  const powers = [1n];
  for (let j = 1; j < half; j++) powers.push(Fp.mul(powers[j - 1], w));
  const lo: number[] = [];
  const hi: number[] = [];
  const tw: bigint[] = [];
  for (let start = 0; start < n; start += size)
    for (let j = 0; j < half; j++) {
      lo.push(start + j);
      hi.push(start + j + half);
      tw.push(powers[j]);
    }
  return { lo, hi, tw };
}

/**
 * Radix-2 FFT over group elements with root `omega` (n = 2^k): the DFT in
 * natural order. Each stage's n/2 twiddle multiplications and n additions
 * run as batches.
 */
export function groupFft(
  points: Point[],
  omega: bigint,
  k: number,
  onStage?: (stage: number) => void,
): Point[] {
  const a = points.slice();
  bitReverse(a);
  const n = 1 << k;
  for (let size = 2, stage = 0; size <= n; size <<= 1, stage++) {
    const { lo, hi, tw } = stageIndices(n, size, omega);
    const [sum, diff] = butterflies(
      lo.map((i) => a[i]),
      hi.map((i) => a[i]),
      tw,
    );
    lo.forEach((i, m) => (a[i] = sum[m]));
    hi.forEach((i, m) => (a[i] = diff[m]));
    onStage?.(stage);
  }
  return a;
}

/** One batch of butterflies: `lo ± tw·hi`. */
export interface ButterflyJob {
  lo: Point[];
  hi: Point[];
  tw: bigint[];
}

/**
 * The parallel steps of `Params::new`, each a list of independent jobs the
 * implementation may run concurrently; results come back in job order.
 */
export interface SrsWorkers {
  /** Parallel lanes. */
  readonly lanes: number;
  /** The generators of each [start, end) range; `onDone` after each range. */
  generators(
    ranges: [number, number][],
    onDone?: () => void,
  ): Promise<Affine[][]>;
  /** One natural-order group DFT per block, with root `omega` of size 2^k. */
  groupFfts(blocks: Point[][], omega: bigint, k: number): Promise<Point[][]>;
  butterflies(jobs: ButterflyJob[]): Promise<[Point[], Point[]][]>;
  /** `s·p` for every point of every chunk. */
  scale(chunks: Point[][], s: bigint): Promise<Point[][]>;
}

/** Contiguous [start, end) ranges splitting `len` items over `parts`. */
function splitRanges(len: number, parts: number): [number, number][] {
  const out: [number, number][] = [];
  const size = Math.ceil(len / parts);
  for (let s = 0; s < len; s += size) out.push([s, Math.min(len, s + size)]);
  return out;
}

/**
 * `Params::new(k)` with its order-free work spread over `workers`. The result
 * is the same key as the serial derivation, point for point: the generators
 * are independent hashes; the inverse FFT runs its first stages as
 * independent sub-transforms of the strided subsequences (the DIT stages below
 * block size B = n/L touch only one bit-reversed block, which is the DFT of
 * the subsequence r, r+L, …), then the remaining stages and the final 1/n
 * scaling as element-wise batches split across lanes.
 */
export async function generateSrsOn(
  workers: SrsWorkers,
  k: number,
  onProgress?: (fraction: number) => void,
): Promise<Srs> {
  const n = 1 << k;
  // Finer than one range per lane, so the bar moves while hashing.
  const ranges = splitRanges(n, workers.lanes * 4);
  let hashed = 0;
  const g = (
    await workers.generators(ranges, () =>
      onProgress?.((++hashed / ranges.length) * 0.5),
    )
  ).flat();

  // L blocks, a power of two not above the lanes or n.
  let l = 0;
  while (l < k && 1 << (l + 1) <= workers.lanes) l++;
  const blocks = 1 << l;
  const b = n >> l;
  const omegaInv = Fp.inv(omegaForSize(k));
  // Block j of the bit-reversed array is the strided subsequence r = rev_l(j).
  const rev = (j: number) => {
    let r = 0;
    for (let i = 0; i < l; i++) r |= ((j >> i) & 1) << (l - 1 - i);
    return r;
  };
  const strided = Array.from({ length: blocks }, (_, j) => {
    const r = rev(j);
    return Array.from({ length: b }, (_, m) => g[r + m * blocks] as Point);
  });
  const subs = await workers.groupFfts(
    strided,
    Fp.pow(omegaInv, BigInt(blocks)),
    k - l,
  );
  const a: Point[] = subs.flat();
  onProgress?.(0.5 + ((k - l) / (k + 1)) * 0.5);

  for (let size = 2 * b, stage = k - l; size <= n; size <<= 1, stage++) {
    const { lo, hi, tw } = stageIndices(n, size, omegaInv);
    const outs = await workers.butterflies(
      splitRanges(lo.length, workers.lanes).map(([s, e]) => ({
        lo: lo.slice(s, e).map((i) => a[i]),
        hi: hi.slice(s, e).map((i) => a[i]),
        tw: tw.slice(s, e),
      })),
    );
    let at = 0;
    for (const [sum, diff] of outs) {
      sum.forEach((p, m) => (a[lo[at + m]] = p));
      diff.forEach((p, m) => (a[hi[at + m]] = p));
      at += sum.length;
    }
    onProgress?.(0.5 + ((stage + 1) / (k + 1)) * 0.5);
  }

  const nInv = Fp.inv(BigInt(n));
  const scaled = (
    await workers.scale(
      splitRanges(n, workers.lanes).map(([s, e]) => a.slice(s, e)),
      nInv,
    )
  ).flat();
  if (scaled.some((q) => q === null))
    throw new Error("identity in the Lagrange basis");
  onProgress?.(1);
  return {
    k,
    g,
    gLagrange: scaled as Affine[],
    w: hashToVesta("Halo2-Parameters", Uint8Array.of(1)),
    u: hashToVesta("Halo2-Parameters", Uint8Array.of(2)),
  };
}

/** `Params::new(k)` on the calling thread. */
export function generateSrs(
  k: number,
  onProgress?: (fraction: number) => void,
): Srs {
  const n = 1 << k;
  const g: Affine[] = [];
  for (let i = 0; i < n; i++) {
    g.push(generator(i));
    if ((i & 63) === 0) onProgress?.((i / n) * 0.5);
  }
  const lagrange = groupFft(g, Fp.inv(omegaForSize(k)), k, (s) =>
    onProgress?.(0.5 + ((s + 1) / (k + 1)) * 0.5),
  );
  const scaled = Vesta.mulEach(Fp.inv(BigInt(n)), lagrange);
  if (scaled.some((q) => q === null))
    throw new Error("identity in the Lagrange basis");
  onProgress?.(1);
  return {
    k,
    g,
    gLagrange: scaled as Affine[],
    w: hashToVesta("Halo2-Parameters", Uint8Array.of(1)),
    u: hashToVesta("Halo2-Parameters", Uint8Array.of(2)),
  };
}
