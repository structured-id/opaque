/**
 * Okamoto representation proof binding the OPAQUE element `M` to the SNARK's
 * Pedersen commitment `Com = H_p + r·G2`. Pure-TS port of Rust
 * `sid_pake_core::binding` (commit-and-prove). Interop-verified against it.
 *
 *   M = α·Com + β·G2 ; honest prover uses α = blind, β = −(blind·r).
 *   challenge c = Fq.from_uniform_bytes(SHA-512(FS_DOMAIN ‖ len(ctx)_LE_u64 ‖ ctx
 *                                               ‖ Com ‖ G2 ‖ M ‖ R))
 *   proof = { R = k1·Com + k2·G2, z1 = k1 + c·α, z2 = k2 + c·β }
 *   verify: z1·Com + z2·G2 == R + c·M
 */
import { sha512 } from '@noble/hashes/sha2.js';
import { Fq } from './field.js';
import { type Point, scalarMul, add, toBytes } from './curve.js';

const FS_DOMAIN = new TextEncoder().encode('SID_ZKPP_COMMIT_PROVE_FS_v1');

/** Decode a little-endian hex string (pasta to_repr) into a field element. */
function leHex(h: string): bigint {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) {
    v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  }
  return v;
}

/**
 * NUMS generator `G2 = hash_to_curve("SID_ZKPP_G2_GENERATOR_v1")(b"")` (pasta_curves).
 * Fixed public constant — hardcoded so the no-WASM client needs no hash-to-curve.
 * Coordinates from `sid-pake-core/tests/interop_vectors.rs`.
 */
export const G2: Point = {
  x: leHex('b5910af07299e793b6e77cd798043fc27c7fd87a1e52f7c7499eef204cd3fe24'),
  y: leHex('2bf91e17a829f947b667b3fa8f58ebd1553a4d16d9a36c96a91c2fdb4148b411'),
};

export interface BindingProof {
  rCommit: Point;
  z1: bigint;
  z2: bigint;
}

function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

/** Fiat-Shamir challenge, byte-identical to the Rust transcript. */
export function challenge(context: Uint8Array, com: Point, m: Point, rCommit: Point): bigint {
  const h = sha512.create();
  h.update(FS_DOMAIN);
  h.update(u64le(context.length));
  h.update(context);
  h.update(toBytes(com));
  h.update(toBytes(G2));
  h.update(toBytes(m));
  h.update(toBytes(rCommit));
  return Fq.fromUniformBytes(h.digest()); // 64-byte SHA-512 digest → Fq
}

/** Verify `z1·Com + z2·G2 == R + c·M`. */
export function verifyBinding(
  context: Uint8Array,
  com: Point,
  m: Point,
  proof: BindingProof,
): boolean {
  const c = challenge(context, com, m, proof.rCommit);
  const lhs = add(scalarMul(proof.z1, com), scalarMul(proof.z2, G2));
  const rhs = add(proof.rCommit, scalarMul(c, m));
  const a = toBytes(lhs);
  const b = toBytes(rhs);
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Prove knowledge of `(α, β)` with `M = α·Com + β·G2`. `nextScalar` returns a random Fq. */
export function proveBinding(
  context: Uint8Array,
  com: Point,
  m: Point,
  alpha: bigint,
  beta: bigint,
  nextScalar: () => bigint,
): BindingProof {
  const k1 = nextScalar();
  const k2 = nextScalar();
  const rCommit = add(scalarMul(k1, com), scalarMul(k2, G2));
  const c = challenge(context, com, m, rCommit);
  const z1 = Fq.add(k1, Fq.mul(c, alpha));
  const z2 = Fq.add(k2, Fq.mul(c, beta));
  return { rCommit, z1, z2 };
}
