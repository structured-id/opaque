// Stage timing of key preparation in the TS client: the commitment key, the
// circuit synthesis with the fixed/permutation commitments, the coefficient
// forms and loading the key into the pool. Run with
// `yarn tsx bench/prepare-profile.ts` for the calling thread, or with
// `LANES=8` for the path the client takes on worker threads.
import { keygen, keygenWith } from "../src/halo2/keygen.js";
import { provingKey } from "../src/halo2/prover.js";
import { generateSrs, generateSrsOn } from "../src/halo2/srs.js";
import { CE_DEFAULT_POLICY } from "../src/zkpp/circuit.js";
import { zkppCircuit } from "../src/zkpp/zkpp-circuit.js";
import { LocalPool } from "../src/halo2/kernel.js";
import { MemoryKeyStore } from "../src/zkpp/key-store.js";
import { ProverCore } from "../src/zkpp/prover-core.js";
import { nodePool } from "../tests/support/node-pool.js";

const ms = (t: number) => `${(performance.now() - t).toFixed(0)} ms`;
const shape = { policy: CE_DEFAULT_POLICY, historyDomains: 1 };
const lanes = Number(process.env.LANES ?? 0);
const total = performance.now();

if (lanes === 0) {
  let t0 = performance.now();
  const srs = generateSrs(11);
  console.log(`srs         ${ms(t0)}`);
  t0 = performance.now();
  const kg = keygen(zkppCircuit(shape), srs);
  console.log(`keygen      ${ms(t0)}`);
  t0 = performance.now();
  provingKey(kg, srs);
  console.log(`provingKey  ${ms(t0)}`);
} else {
  const pool = nodePool(lanes);
  // Start the workers first: their start-up is not part of the derivation.
  let t0 = performance.now();
  await pool.generators(
    Array.from({ length: lanes }, (_, i): [number, number] => [i, i + 1]),
  );
  console.log(`lane start  ${ms(t0)}`);
  t0 = performance.now();
  let hashed = 0;
  const marks: string[] = [];
  const srs = await generateSrsOn(pool, 11, (f) => {
    if (f >= 0.5 && hashed === 0) hashed = performance.now();
    if (f >= 0.5) marks.push(`${f.toFixed(3)}@${ms(t0)}`);
  });
  if (process.env.MARKS) console.log(marks.join(" "));
  console.log(
    `srs         ${ms(t0)} (${lanes} lanes; hash-to-curve ${(hashed - t0).toFixed(0)} ms, FFT ${(performance.now() - hashed).toFixed(0)} ms)`,
  );
  t0 = performance.now();
  await pool.init(srs);
  console.log(`pool init   ${ms(t0)}`);
  t0 = performance.now();
  const kg = await keygenWith(zkppCircuit(shape), srs, (polys) =>
    pool.msmMany(polys, "lagrange"),
  );
  console.log(`keygen      ${ms(t0)}`);
  t0 = performance.now();
  const pk = provingKey(kg, srs);
  console.log(`provingKey  ${ms(t0)}`);
  t0 = performance.now();
  const qpd = (1 << pk.keygen.extendedK) >> pk.keygen.k;
  await pool.loadKey(pk.id, { shape: pk.shape, polys: pk.polys }, qpd);
  console.log(`loadKey     ${ms(t0)}`);
  pool.close();
}
console.log(`total       ${ms(total)}`);

// A later visit: the client's prepare over a store that already holds the key.
const store = new MemoryKeyStore();
const visit = async () => {
  const pool = lanes > 0 ? nodePool(lanes) : new LocalPool();
  const t0 = performance.now();
  await new ProverCore(pool, undefined, store).prepare(1, 1);
  const t = ms(t0);
  pool.close();
  return t;
};
console.log(`client, first visit  ${await visit()}`);
console.log(`client, later visit  ${await visit()}`);
