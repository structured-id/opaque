/**
 * The OPRF of OPAQUE on Pallas (voprf `PallasVoprf`, suite
 * "Pallas-Poseidon-SHA256"), client side, byte-identical to the Rust reference
 * `sid_pake_core::pallas_opaque` over voprf 0.5 (RFC 9497, base mode).
 *
 * Hash-to-group is the circuit's Poseidon hash-to-curve of the password
 * zero-padded to MAX_PASSWORD_LEN, so the registration element is the value
 * the ZKPP proof computes (the DST is not used there). Hash-to-scalar is RFC
 * 9380 expand_message_xmd with SHA-256 to 64 bytes, reduced into the scalar
 * field.
 */
import { expand_message_xmd } from "@noble/curves/abstract/hash-to-curve.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Pallas, type Point } from "../curve.js";
import { Fq } from "../field.js";
import { hashToCurveOutside } from "../hash-to-curve.js";
import type { RandomSource } from "../random.js";
import { concat, i2osp2, utf8 } from "./bytes.js";

/** Longest password the circuit holds; shorter ones are zero-padded to it. */
export const MAX_PASSWORD_LEN = 128;

/** Longest OPRF input (RFC 9497 §5.1: smaller than 2^16 - 1 bytes). */
export const MAX_OPRF_INPUT = 0xfffe;

/** voprf `CipherSuite::ID`. */
const SUITE_ID = utf8("Pallas-Poseidon-SHA256");

/** contextString = "OPRFV1-" ‖ mode ‖ "-" ‖ suite (RFC 9497 §3.1), base mode. */
function dst(prefix: string): Uint8Array {
  return concat([
    utf8(prefix),
    utf8("OPRFV1-"),
    Uint8Array.of(0),
    utf8("-"),
    SUITE_ID,
  ]);
}

/** A group element as sent: compressed, 32 bytes. */
export const serializeElement = (p: Point): Uint8Array => Pallas.toBytes(p);

/** A received group element; the identity is refused (RFC 9497 §2.1). */
export function deserializeElement(bytes: Uint8Array): NonNullable<Point> {
  if (bytes.length !== 32) throw new Error("element: must be 32 bytes");
  const p = Pallas.fromBytes(bytes);
  if (p === null) throw new Error("element: the identity is not accepted");
  return p;
}

/** A scalar as sent: 32 bytes little-endian. */
export const serializeScalar = (s: bigint): Uint8Array => Fq.toBytes(s);

/** A received scalar: canonical and nonzero. */
export function deserializeScalar(bytes: Uint8Array): bigint {
  const s = Fq.fromBytes(bytes);
  if (s === 0n) throw new Error("scalar: zero is not accepted");
  return s;
}

/** `Scalar::random`: 64 uniform bytes reduced into the scalar field. */
export const randomScalar = (rng: RandomSource): bigint =>
  Fq.fromUniformBytes(rng(64));

/**
 * Hash-to-group of the password as the circuit hashes it. Zero padding makes
 * `P` and `P` followed by NUL bytes one element, unlike RFC 9497's
 * length-prefixed hashing: the proof covers this element, while Finalize
 * (which sees the input as given) stays client-side and unproven by design.
 */
export function hashToGroup(input: Uint8Array): NonNullable<Point> {
  if (input.length === 0) throw new Error("oprf: empty input");
  // RFC 9497 §5.1: inputs MUST be smaller than 2^16 - 1 bytes. Refused here,
  // before any message, rather than at Finalize after the server answered.
  if (input.length > MAX_OPRF_INPUT) throw new Error("oprf: password too long");
  const padded =
    input.length < MAX_PASSWORD_LEN ? new Uint8Array(MAX_PASSWORD_LEN) : input;
  if (padded !== input) padded.set(input);
  return hashToCurveOutside(padded).point;
}

/** Hash-to-scalar over the concatenated `input` under `dstBytes`. */
export function hashToScalar(input: Uint8Array, dstBytes: Uint8Array): bigint {
  if (input.length === 0) throw new Error("oprf: empty input");
  return Fq.fromUniformBytes(expand_message_xmd(input, dstBytes, 64, sha256));
}

/**
 * DeriveKeyPair's scalar (RFC 9497 §3.2.1): the first nonzero
 * hash-to-scalar of `seed ‖ I2OSP(len(info), 2) ‖ info ‖ counter`.
 */
export function deriveKey(seed: Uint8Array, info: Uint8Array): bigint {
  const d = dst("DeriveKeyPair");
  for (let counter = 0; counter < 256; counter++) {
    const sk = hashToScalar(
      concat([seed, i2osp2(info.length), info, Uint8Array.of(counter)]),
      d,
    );
    if (sk !== 0n) return sk;
  }
  throw new Error("oprf: DeriveKeyPair found no nonzero scalar");
}

/** Blind(input) with a given blind: the blinded element `blind·H(input)`. */
export function blindWith(input: Uint8Array, blind: bigint): Uint8Array {
  return serializeElement(Pallas.scalarMul(blind, hashToGroup(input)));
}

/**
 * Finalize (RFC 9497 §3.3.1): unblind the evaluated element and hash
 * `I2OSP(len(input), 2) ‖ input ‖ I2OSP(32, 2) ‖ N ‖ "Finalize"`.
 */
export function finalize(
  input: Uint8Array,
  blind: bigint,
  evaluated: Uint8Array,
): Uint8Array {
  const z = deserializeElement(evaluated);
  const n = Pallas.scalarMul(Fq.inv(blind), z);
  return sha256(
    concat([
      i2osp2(input.length),
      input,
      i2osp2(32),
      serializeElement(n),
      utf8("Finalize"),
    ]),
  );
}
