// Stage timing of the TS prover on the recorded reference proof; run with
// `yarn tsx bench/prove-profile.ts` (add `node --cpu-prof` through tsx for a profile).
import { readFileSync } from "fs";
import { Pallas, Vesta, type Point } from "../src/curve.js";
import { Fp } from "../src/field.js";
import { keygen, type Srs } from "../src/halo2/keygen.js";
import { createProof, provingKey } from "../src/halo2/prover.js";
import { historyInput } from "../src/history.js";
import {
  CE_DEFAULT_POLICY,
  MAX_PASSWORD_LEN,
  historyWitness,
} from "../src/zkpp/circuit.js";
import { zkppCircuit } from "../src/zkpp/zkpp-circuit.js";
import { nodePool } from "../tests/support/node-pool.js";

const fixture = (name: string) =>
  new URL(`../tests/fixtures/${name}`, import.meta.url);
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
    return p as NonNullable<Point>;
  };
  const g = Array.from({ length: n }, point);
  const gLagrange = Array.from({ length: n }, point);
  return { k, g, gLagrange, w: point(), u: point() };
}

const v = JSON.parse(readFileSync(fixture("proof-vector.json"), "utf8"));
const drawn = new Uint8Array(readFileSync(fixture("proof-rng.bin")));
let at = 0;
const rng = (n: number) => {
  const out = drawn.slice(at, at + n);
  at += n;
  return out;
};

const srs = readSrs();
const shape = { policy: CE_DEFAULT_POLICY, historyDomains: 1 };
let t0 = performance.now();
const kg = keygen(zkppCircuit(shape), srs);
console.log(`keygen      ${(performance.now() - t0).toFixed(0)} ms`);
t0 = performance.now();
const pk = provingKey(kg, srs);
console.log(`provingKey  ${(performance.now() - t0).toFixed(0)} ms`);

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

// `LANES=8 yarn tsx bench/prove-profile.ts` proves on worker threads.
const lanes = Number(process.env.LANES ?? 0);
const pool = lanes > 0 ? nodePool(lanes) : undefined;
if (pool) {
  t0 = performance.now();
  await pool.init(srs);
  console.log(
    `pool init   ${(performance.now() - t0).toFixed(0)} ms (${lanes} lanes)`,
  );
}

// With a pool the key stays loaded, so the second run is the warm proof.
for (let run = 0; run < (pool ? 2 : 1); run++) {
  at = 0;
  let stage = "";
  let stageStart = performance.now();
  const proveStart = performance.now();
  const proof = await createProof(
    pk,
    zkppCircuit(shape, witness),
    instances,
    rng,
    {
      context: [fe(v.context)],
      pool,
      onProgress: (s) => {
        if (s === stage) return;
        const now = performance.now();
        if (stage)
          console.log(
            `  ${stage.padEnd(16)}${(now - stageStart).toFixed(0)} ms`,
          );
        stage = s;
        stageStart = now;
      },
    },
  );
  const end = performance.now();
  console.log(`  ${stage.padEnd(16)}${(end - stageStart).toFixed(0)} ms`);
  console.log(`prove       ${(end - proveStart).toFixed(0)} ms`);
  console.log(hex(proof) === v.proof ? "proof: identical" : "proof: MISMATCH");
}
pool?.close();
