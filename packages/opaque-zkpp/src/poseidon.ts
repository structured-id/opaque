/**
 * Poseidon over the Pallas base field — P128Pow5T3 spec (t=3, rate=2, Pow5 S-box,
 * 8 full + 56 partial rounds), byte-identical to `halo2_gadgets` /
 * `sid_pake_core::poseidon`. Round constants + MDS are dumped from the Rust spec.
 *
 * Sponge = ConstantLength<L>: state = [in_0, in_1, capacity=L·2^64], one permutation,
 * output state[0]. Verified against the Rust hash vectors.
 */
import { Fp } from './field.js';
import { POSEIDON_RC, POSEIDON_MDS } from './poseidon-constants.js';

const T = 3;
const RATE = 2;
const R_F = 8;
const R_P = 56;
const HALF_F = R_F / 2;

/** Pow5 S-box: x^5. */
function sbox(x: bigint): bigint {
  const x2 = Fp.square(x);
  return Fp.mul(Fp.square(x2), x);
}

function applyMds(state: bigint[]): void {
  const o0 = Fp.add(
    Fp.add(Fp.mul(POSEIDON_MDS[0][0], state[0]), Fp.mul(POSEIDON_MDS[0][1], state[1])),
    Fp.mul(POSEIDON_MDS[0][2], state[2]),
  );
  const o1 = Fp.add(
    Fp.add(Fp.mul(POSEIDON_MDS[1][0], state[0]), Fp.mul(POSEIDON_MDS[1][1], state[1])),
    Fp.mul(POSEIDON_MDS[1][2], state[2]),
  );
  const o2 = Fp.add(
    Fp.add(Fp.mul(POSEIDON_MDS[2][0], state[0]), Fp.mul(POSEIDON_MDS[2][1], state[1])),
    Fp.mul(POSEIDON_MDS[2][2], state[2]),
  );
  state[0] = o0;
  state[1] = o1;
  state[2] = o2;
}

function permute(state: bigint[]): void {
  let round = 0;
  const full = () => {
    for (let i = 0; i < T; i++) state[i] = Fp.add(state[i], POSEIDON_RC[round][i]);
    for (let i = 0; i < T; i++) state[i] = sbox(state[i]);
    applyMds(state);
    round++;
  };
  const partial = () => {
    for (let i = 0; i < T; i++) state[i] = Fp.add(state[i], POSEIDON_RC[round][i]);
    state[0] = sbox(state[0]); // partial round: S-box on state[0] only
    applyMds(state);
    round++;
  };
  for (let r = 0; r < HALF_F; r++) full();
  for (let r = 0; r < R_P; r++) partial();
  for (let r = 0; r < HALF_F; r++) full();
}

/** Pow5 chip witness cells: state at each round-row + the partial-round sboxes. */
export interface Pow5Cells {
  /** State [s0,s1,s2] per row: load + HALF_F + (R_P/2) partial-pairs + HALF_F. */
  states: bigint[][];
  /** First-round sbox r[0] of each partial-round pair (the partial_sbox column). */
  partialSbox: bigint[];
}

/**
 * Run the Poseidon permutation recording the halo2_gadgets Pow5 chip layout: the
 * state after the load row, after each full round, and after each compressed
 * partial-round PAIR, plus each pair's first-round sbox value.
 */
export function permuteWithCells(initial: bigint[]): Pow5Cells {
  const state = initial.map((v) => Fp.mod(v));
  const states: bigint[][] = [state.slice()];
  const partialSbox: bigint[] = [];
  let round = 0;
  const full = () => {
    for (let i = 0; i < T; i++) state[i] = Fp.add(state[i], POSEIDON_RC[round][i]);
    for (let i = 0; i < T; i++) state[i] = sbox(state[i]);
    applyMds(state);
    round++;
  };
  const partial = () => {
    for (let i = 0; i < T; i++) state[i] = Fp.add(state[i], POSEIDON_RC[round][i]);
    state[0] = sbox(state[0]);
    applyMds(state);
    round++;
  };
  for (let r = 0; r < HALF_F; r++) {
    full();
    states.push(state.slice());
  }
  for (let r = 0; r < R_P / 2; r++) {
    partialSbox.push(sbox(Fp.add(state[0], POSEIDON_RC[round][0])));
    partial();
    partial();
    states.push(state.slice());
  }
  for (let r = 0; r < HALF_F; r++) {
    full();
    states.push(state.slice());
  }
  return { states, partialSbox };
}

/** ConstantLength<L> hash: capacity = L·2^64, single permutation, output lane 0. */
function hashConstLen(inputs: bigint[]): bigint {
  const L = inputs.length;
  const state = [0n, 0n, BigInt(L) << 64n]; // capacity element at index RATE
  for (let i = 0; i < RATE; i++) {
    state[i] = Fp.add(state[i], i < L ? Fp.mod(inputs[i]) : 0n);
  }
  permute(state);
  return state[0];
}

export function poseidonHash2(a: bigint, b: bigint): bigint {
  return hashConstLen([a, b]);
}

export function poseidonHash1(a: bigint): bigint {
  return hashConstLen([a]);
}

/** Iterative pair hashing: H(H(H(e0,e1),e2),...). Mirrors Rust poseidon_hash_chain. */
export function hashChain(elements: bigint[]): bigint {
  if (elements.length === 0) throw new Error('poseidon hashChain: empty input');
  if (elements.length === 1) return poseidonHash1(elements[0]);
  let acc = poseidonHash2(elements[0], elements[1]);
  for (let i = 2; i < elements.length; i++) acc = poseidonHash2(acc, elements[i]);
  return acc;
}

/** Pack bytes into Pallas base elements, 31 bytes each, little-endian. */
export function bytesToFieldElements(bytes: Uint8Array): bigint[] {
  const out: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    const repr = new Uint8Array(32);
    repr.set(bytes.subarray(i, i + 31));
    out.push(Fp.fromBytes(repr));
  }
  return out;
}

/** PoseidonHash(password_bytes ‖ salt_bytes) — history commitment. */
export function computeHistoryCommitment(password: Uint8Array, salt: Uint8Array): bigint {
  const fes = bytesToFieldElements(password).concat(bytesToFieldElements(salt));
  return hashChain(fes);
}
