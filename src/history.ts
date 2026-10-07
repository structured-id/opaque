/**
 * Client side of the private password history, byte-identical to the Rust
 * reference `sid_pake_core::history`:
 *
 *   u = Poseidon(d, Poseidon(P))            d: the operation's owner domain
 *   H = canonical_point(u)                  first offset, even y
 *   B = r·H,  Z = k·B,  N = r⁻¹·Z = k·H
 *   t = Poseidon(c, u, x(N))                c: a comparison domain
 *
 * The client sends B, checks that each answer Z carries a valid proof under
 * its domain's evaluator key for this operation, and proves t in the circuit.
 */
import { expand_message_xmd } from "@noble/curves/abstract/hash-to-curve.js";
import { Field as NobleField } from "@noble/curves/abstract/modular.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Pallas, type Point } from "./curve.js";
import { Fp, FP_MODULUS, Fq } from "./field.js";
import { bytesToFieldElements, hashChain, poseidonHash2 } from "./poseidon.js";
import type { RandomSource } from "./random.js";
import { MAX_PASSWORD_LEN } from "./opaque/oprf.js";

const NFp = NobleField(FP_MODULUS);
const B = 5n;
/** Hash-to-curve tries 2^8 offsets from `u`. */
const HTC_TRIES = 256n;
const DLEQ_DST = new TextEncoder().encode("SID-HISTORY-VOPRF-DLEQ-v1");

function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Poseidon over `purpose` and each part, every field length-prefixed. */
export function domainElement(
  purpose: Uint8Array,
  parts: Uint8Array[],
): bigint {
  const fields = [purpose, ...parts].flatMap((f) => [u32le(f.length), f]);
  return hashChain(bytesToFieldElements(concat(fields)));
}

/** The password as the circuit packs it: zero-padded, 31 bytes per element. */
export function passwordElements(password: Uint8Array): bigint[] {
  if (password.length > MAX_PASSWORD_LEN)
    throw new Error("password longer than the circuit holds");
  const padded = new Uint8Array(MAX_PASSWORD_LEN);
  padded.set(password);
  return bytesToFieldElements(padded);
}

/** `u = Poseidon(d, Poseidon(P))` for the owner domain `d`. */
export function historyInput(d: bigint, password: Uint8Array): bigint {
  return poseidonHash2(d, hashChain(passwordElements(password)));
}

/**
 * The first curve point at `x = u + offset` with the even `y`, and that
 * offset. Every offset is tested, so the work does not depend on `u`.
 */
export function canonicalPoint(u: bigint): {
  point: NonNullable<Point>;
  offset: bigint;
} {
  let found: { point: NonNullable<Point>; offset: bigint } | null = null;
  for (let i = 0n; i < HTC_TRIES; i++) {
    const x = Fp.add(u, i);
    const y2 = Fp.add(Fp.mul(Fp.square(x), x), B);
    const square = y2 === 0n || Fp.pow(y2, (FP_MODULUS - 1n) / 2n) === 1n;
    if (square && found === null) {
      const y = NFp.sqrt(y2);
      found = { point: { x, y: y & 1n ? Fp.neg(y) : y }, offset: i };
    }
  }
  if (found === null) throw new Error("no curve point within the try range");
  return found;
}

/** A fresh nonzero blind drawn from the base field. */
export function randomBlind(rng: RandomSource): bigint {
  for (;;) {
    const r = Fp.fromUniformBytes(rng(64));
    if (r !== 0n) return r;
  }
}

/** The client request `B = r·H`, the blind read as a scalar. */
export function blindRequest(u: bigint, r: bigint): NonNullable<Point> {
  const b = Pallas.scalarMul(r, canonicalPoint(u).point);
  if (b === null) throw new Error("blind request: identity");
  return b;
}

/** The Chaum-Pedersen challenge over pk, B, Z, T2, T3, bound to `context`. */
function challenge(context: Uint8Array, points: Point[]): bigint {
  const msg = concat([
    u32le(context.length),
    context,
    ...points.map(Pallas.toBytes),
  ]);
  return Fq.fromUniformBytes(expand_message_xmd(msg, DLEQ_DST, 64, sha256));
}

/** Whether `Z = k·B` for the `k` behind `pk`, proved for the operation `context`. */
export function verifyEvaluation(
  pk: Point,
  b: Point,
  z: Point,
  context: Uint8Array,
  proof: { c: bigint; s: bigint },
): boolean {
  const G = Pallas.GENERATOR;
  const t2 = Pallas.add(
    Pallas.scalarMul(proof.s, G),
    Pallas.scalarMul(proof.c, pk),
  );
  const t3 = Pallas.add(
    Pallas.scalarMul(proof.s, b),
    Pallas.scalarMul(proof.c, z),
  );
  return challenge(context, [pk, b, z, t2, t3]) === proof.c;
}

/** Unblind `N = r⁻¹·Z` and derive the tag `t = Poseidon(c, u, x(N))`. */
export function finalizeTag(c: bigint, u: bigint, r: bigint, z: Point): bigint {
  const n = Pallas.scalarMul(Fq.inv(r), z);
  if (n === null) throw new Error("history: N is the identity");
  return hashChain([c, u, n.x]);
}
