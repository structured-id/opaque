/**
 * What one registration proof states and is bound to, as the reference
 * computes it (`sid_pake_core::binding`, `ZkppCircuit::instance_values`):
 *
 *   context   = "SID_ZKPP_PASSWORD_OPERATION_v1" ‖ operation id ‖ request
 *   absorbed  = from_uniform(SHA-512("SID_ZKPP_TRANSCRIPT_CONTEXT_v1" ‖ u64le(len) ‖ context))
 *   instances = M.x, M.y, d, c_1..c_D, B.x, B.y, (Z_j.x, Z_j.y, t_j) per domain
 *
 * with M = blind·H(P) the OPAQUE registration element, B = r·H(u) the history
 * request and Z_j = r·N_j, t_j = Poseidon(c_j, u, N_j.x) its tags.
 */
import { sha512 } from "@noble/hashes/sha2.js";
import { Pallas, type Point } from "../curve.js";
import { Fp } from "../field.js";
import { hashToCurveOutside } from "../hash-to-curve.js";
import { historyInput } from "../history.js";
import { hashChain } from "../poseidon.js";
import {
  CE_DEFAULT_POLICY,
  MAX_PASSWORD_LEN,
  type HistoryTagWitness,
  type PolicyParams,
} from "./circuit.js";

const enc = new TextEncoder();
const OPERATION_CONTEXT_DOMAIN = enc.encode("SID_ZKPP_PASSWORD_OPERATION_v1");
const TRANSCRIPT_CONTEXT_DOMAIN = enc.encode("SID_ZKPP_TRANSCRIPT_CONTEXT_v1");

/** The policy a version names (`sid_crypto::policy::get_policy`). */
export function policyOf(version: number): PolicyParams {
  if (version === 1) return CE_DEFAULT_POLICY;
  throw new Error(`policy version ${version} not found`);
}

/** The binding context of a password operation and its OPAQUE request. */
export function operationContext(
  operationId: Uint8Array,
  request: Uint8Array,
): Uint8Array {
  if (operationId.length !== 16)
    throw new Error("operation id must be 16 bytes");
  const out = new Uint8Array(
    OPERATION_CONTEXT_DOMAIN.length + 16 + request.length,
  );
  out.set(OPERATION_CONTEXT_DOMAIN, 0);
  out.set(operationId, OPERATION_CONTEXT_DOMAIN.length);
  out.set(request, OPERATION_CONTEXT_DOMAIN.length + 16);
  return out;
}

/** The scalar the transcript absorbs for `context`, before any proof message. */
export function transcriptContext(context: Uint8Array): bigint {
  const len = new Uint8Array(8);
  new DataView(len.buffer).setBigUint64(0, BigInt(context.length), true);
  const h = sha512
    .create()
    .update(TRANSCRIPT_CONTEXT_DOMAIN)
    .update(len)
    .update(context)
    .digest();
  return Fp.fromUniformBytes(h);
}

const affine = (p: Point, what: string): NonNullable<Point> => {
  if (p === null) throw new Error(`${what} is the identity`);
  return p;
};

/** The public instances of a proof, in the circuit's order. */
export function zkppInstances(
  password: Uint8Array,
  blind: bigint,
  d: bigint,
  domains: bigint[],
  history: HistoryTagWitness,
): bigint[] {
  if (password.length > MAX_PASSWORD_LEN)
    throw new Error("password longer than the circuit holds");
  const padded = new Uint8Array(MAX_PASSWORD_LEN);
  padded.set(password);
  const m = affine(
    Pallas.scalarMul(blind, hashToCurveOutside(padded).point),
    "M",
  );
  const u = historyInput(d, password);
  const b = affine(Pallas.scalarMul(history.r, history.h), "B");
  const out = [m.x, m.y, d, ...domains, b.x, b.y];
  domains.forEach((c, j) => {
    const n = history.n[j];
    const z = affine(Pallas.scalarMul(history.r, n), "Z");
    out.push(z.x, z.y, hashChain([c, u, n.x]));
  });
  return out;
}
