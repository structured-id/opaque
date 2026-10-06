// The bench's prover, off the page's main thread: derives the SRS and the key,
// then proves the recorded reference registration on the lanes whose ports
// the page hands over, and on its own thread, checking every proof against
// the Rust bytes. Lines go to the page and to the bench host's /log.
import { Pallas, type Point } from "../../src/curve.js";
import { Fp, FP_MODULUS } from "../../src/field.js";
import { keygen } from "../../src/halo2/keygen.js";
import { createProof, provingKey } from "../../src/halo2/prover.js";
import { generateSrs } from "../../src/halo2/srs.js";
import { WorkerPool, type LaneWorker } from "../../src/halo2/lanes.js";
import { historyInput } from "../../src/history.js";
import {
  CE_DEFAULT_POLICY,
  MAX_PASSWORD_LEN,
  historyWitness,
} from "../../src/zkpp/circuit.js";
import { zkppCircuit } from "../../src/zkpp/zkpp-circuit.js";

interface Start {
  dev: string;
  rounds: number;
  single: boolean;
  ports: MessagePort[];
}

const unhex = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/.{2}/g) ?? [], (b) => parseInt(b, 16));
const hex = (b: Uint8Array): string =>
  [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
const fe = (h: string) => Fp.fromBytes(unhex(h));
const ms = (t0: number) => `${(performance.now() - t0).toFixed(0)} ms`;

function mulBench(): string {
  const xs: bigint[] = [];
  let s = 0x1234567890abcdef1234567890abcdefn;
  for (let i = 0; i < 256; i++) {
    s = (s * s + 7n) % FP_MODULUS;
    xs.push(s);
  }
  const N = 300_000;
  let acc = xs[0];
  for (let i = 0; i < 20_000; i++) acc = Fp.mul(acc, xs[i & 255]);
  const t0 = performance.now();
  for (let i = 0; i < N; i++) acc = Fp.mul(acc, xs[i & 255]);
  const ns = ((performance.now() - t0) * 1e6) / N;
  return `${ns.toFixed(0)} ns (${acc & 1n})`;
}

async function run({ dev, rounds, single, ports }: Start) {
  const log = (m: string) => {
    postMessage(m);
    fetch("/log", { method: "POST", body: `[${dev} | ts] ${m}` }).catch(
      () => undefined,
    );
  };
  log(
    `UA: ${navigator.userAgent} | cores: ${navigator.hardwareConcurrency} | lanes ${ports.length} | rounds ${rounds} | orchestrator in a worker`,
  );
  log(`Fp.mul (worker): ${mulBench()}`);
  const v = await (await fetch("./proof-vector.json")).json();
  const drawn = new Uint8Array(
    await (await fetch("./proof-rng.bin")).arrayBuffer(),
  );

  let t0 = performance.now();
  const srs = generateSrs(11);
  log(`srs ${ms(t0)}`);
  const shape = { policy: CE_DEFAULT_POLICY, historyDomains: 1 };
  t0 = performance.now();
  const kg = keygen(zkppCircuit(shape), srs);
  log(`keygen ${ms(t0)}`);
  const pk = provingKey(kg, srs);

  const pw = unhex(v.password);
  const password = new Uint8Array(MAX_PASSWORD_LEN);
  password.set(pw);
  const d = fe(v.d);
  const witness = {
    password,
    passwordLen: pw.length,
    blind: fe(v.blind),
    d,
    domains: [fe(v.c)],
    history: historyWitness(historyInput(d, pw), fe(v.r), [
      Pallas.fromBytes(unhex(v.z)) as NonNullable<Point>,
    ]),
    breachBits: new Array(256).fill(0),
  };
  const instances = (v.instances as string[]).map(fe);

  const prove = async (label: string, pool?: WorkerPool) => {
    let at = 0;
    const rng = (n: number) => {
      const r = drawn.slice(at, at + n);
      at += n;
      return r;
    };
    const stages: string[] = [];
    let stage = "";
    let since = performance.now();
    const t = performance.now();
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
          if (stage) stages.push(`${stage} ${(now - since).toFixed(0)}`);
          stage = s;
          since = now;
        },
      },
    );
    stages.push(`${stage} ${(performance.now() - since).toFixed(0)}`);
    const ok = hex(proof) === v.proof && at === drawn.length;
    log(
      `${label}: ${ms(t)} ${ok ? "identical" : "MISMATCH"} | ${stages.join(" / ")}`,
    );
  };

  if (ports.length > 1) {
    t0 = performance.now();
    let next = 0;
    const pool = new WorkerPool(() => {
      const port = ports[next++];
      const lane: LaneWorker = {
        postMessage: (m) => port.postMessage(m),
        onmessage: null,
        terminate: () => port.close(),
      };
      port.onmessage = (e) => lane.onmessage?.(e);
      return lane;
    }, ports.length);
    await pool.init(srs);
    log(`pool init ${ms(t0)}`);
    for (let r = 1; r <= rounds; r++)
      await prove(`lanes ${ports.length} #${r}`, pool);
    pool.close();
  }
  if (single) await prove("single thread");
  log("DONE");
}

self.onmessage = (e: MessageEvent) => {
  run(e.data as Start).catch((err) =>
    postMessage(`ERROR ${err instanceof Error ? err.stack : String(err)}`),
  );
};
