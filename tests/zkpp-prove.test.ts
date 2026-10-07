// The TS prover against the Rust reference: fixtures/proof-vector.json holds a
// registration proof the reference prover made (CE policy, one history
// domain), with its inputs, public instances and operation context, and
// fixtures/proof-rng.bin every byte its RNG handed out, in order (from the
// sid-pake-core `proof_vectors` example; the Rust verifier accepted it).
// Replaying that stream over a witness built from the same inputs, the TS
// prover must write the same proof bytes and consume exactly that stream,
// both on the calling thread and on a pool of worker lanes (three lanes, so
// the eight coset classes split unevenly and lone MSMs are cut in parts).
import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "fs";
import { Pallas, Vesta, type Point } from "../src/curve.js";
import { Fp } from "../src/field.js";
import { keygen, type Srs } from "../src/halo2/keygen.js";
import {
  createProof,
  provingKey,
  type ProvingKey,
} from "../src/halo2/prover.js";
import type { ProverPool } from "../src/halo2/kernel.js";
import { historyInput } from "../src/history.js";
import {
  CE_DEFAULT_POLICY,
  MAX_PASSWORD_LEN,
  historyWitness,
} from "../src/zkpp/circuit.js";
import { zkppCircuit } from "../src/zkpp/zkpp-circuit.js";
import { nodePool } from "./support/node-pool.js";

const fixture = (name: string) =>
  new URL(`./fixtures/${name}`, import.meta.url);
const unhex = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/.{2}/g) ?? [], (b) => parseInt(b, 16));
const hex = (b: Uint8Array): string =>
  [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
const fe = (h: string) => Fp.fromBytes(unhex(h));

function readSrs(): Srs {
  const bytes = readFileSync(fixture("srs-k11.bin"));
  const k = bytes.readUInt32LE(0);
  const n = 1 << k;
  let at = 4;
  const point = (): NonNullable<Point> => {
    const p = Vesta.fromBytes(new Uint8Array(bytes.subarray(at, at + 32)));
    at += 32;
    if (p === null) throw new Error("identity in the SRS");
    return p;
  };
  const g = Array.from({ length: n }, point);
  const gLagrange = Array.from({ length: n }, point);
  return { k, g, gLagrange, w: point(), u: point() };
}

const v = JSON.parse(readFileSync(fixture("proof-vector.json"), "utf8"));
const drawn = new Uint8Array(readFileSync(fixture("proof-rng.bin")));
const shape = { policy: CE_DEFAULT_POLICY, historyDomains: 1 };
let srs: Srs;
let pk: ProvingKey;

beforeAll(() => {
  srs = readSrs();
  pk = provingKey(keygen(zkppCircuit(shape), srs), srs);
}, 600000);

/** Prove the reference inputs replaying the recorded stream. */
async function proveReference(pool?: ProverPool) {
  let at = 0;
  const rng = (n: number) => {
    if (at + n > drawn.length) throw new Error("drew past the stream");
    const out = drawn.slice(at, at + n);
    at += n;
    return out;
  };
  const pw = unhex(v.password);
  const password = new Uint8Array(MAX_PASSWORD_LEN);
  password.set(pw);
  const d = fe(v.d);
  const u = historyInput(d, pw);
  const witness = {
    password,
    passwordLen: pw.length,
    blind: fe(v.blind),
    d,
    domains: [fe(v.c)],
    history: historyWitness(u, fe(v.r), [
      Pallas.fromBytes(unhex(v.z)) as NonNullable<Point>,
    ]),
    breachBits: new Array(256).fill(0),
  };
  const instances = (v.instances as string[]).map(fe);
  const proof = await createProof(
    pk,
    zkppCircuit(shape, witness),
    instances,
    rng,
    { context: [fe(v.context)], pool },
  );
  return { proof: hex(proof), consumed: at };
}

describe("ZKPP prover matches the Rust reference", () => {
  it("writes the reference proof from the recorded RNG stream", async () => {
    const { proof, consumed } = await proveReference();
    expect(proof).toBe(v.proof);
    expect(consumed).toBe(drawn.length);
  }, 1800000);

  it("writes the same proof on worker lanes", async () => {
    const pool = nodePool(3);
    try {
      await pool.init(srs);
      const { proof, consumed } = await proveReference(pool);
      expect(proof).toBe(v.proof);
      expect(consumed).toBe(drawn.length);
    } finally {
      pool.close();
    }
  }, 1800000);
});
