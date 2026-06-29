/**
 * Gadget D (breach bloom) — tractable witness: breach_hash (Poseidon chain over
 * the padded password), the 255-bit decomposition of the hash, and the k Bloom
 * indices (disjoint index_bits-wide slices of the low bits). The Pow5 Poseidon
 * in-circuit chip cells + the Bloom lookup are separate (chip / data).
 */
import { Fp } from '../field.js';
import { hashChain, bytesToFieldElements } from '../poseidon.js';

export const HASH_BITS = 255;

/** Poseidon hash of the password zero-padded to padLen, packed to field elements. */
export function breachHash(pw: number[], padLen: number): bigint {
  const buf = new Uint8Array(padLen);
  buf.set(pw.slice(0, Math.min(pw.length, padLen)));
  return hashChain(bytesToFieldElements(buf));
}

/** Little-endian bit decomposition of a field element (HASH_BITS bits). */
export function hashBits(hash: bigint): number[] {
  const repr = Fp.toBytes(hash); // 32 bytes LE
  return Array.from({ length: HASH_BITS }, (_, j) => (repr[j >> 3] >> (j & 7)) & 1);
}

/** k Bloom indices: disjoint index_bits-wide slices of the low hash bits. */
export function bloomIndices(hash: bigint, k: number, indexBits: number): number[] {
  const bits = hashBits(hash);
  return Array.from({ length: k }, (_, i) => {
    let idx = 0;
    for (let l = 0; l < indexBits; l++) idx |= bits[i * indexBits + l] << l;
    return idx;
  });
}
