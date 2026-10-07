/**
 * The TypeScript prover service: derives the commitment key and a proving
 * key per circuit shape on first use (no artifact comes from the server),
 * keeps them for later proofs, and proves registration jobs on a pool.
 * The same core runs in the prover worker and, where no Web Worker exists,
 * on the calling thread.
 */
import { Pallas, type Point } from "../curve.js";
import { MAX_PASSWORD_LEN } from "../opaque/oprf.js";
import { historyInput } from "../history.js";
import { secureRandom, type RandomSource } from "../random.js";
import {
  keygenColumns,
  keygenFinish,
  withDefaultBlind,
  type Srs,
} from "../halo2/keygen.js";
import { createProof, provingKey, type ProvingKey } from "../halo2/prover.js";
import { generateSrsOn } from "../halo2/srs.js";
import { LocalPool, type ProverPool } from "../halo2/kernel.js";
import {
  columnsDigest,
  decodeCommitments,
  decodeSrs,
  encodeCommitments,
  encodeSrs,
} from "./key-cache.js";
import { MemoryKeyStore, type KeyStore } from "./key-store.js";
import { historyWitness } from "./circuit.js";
import { zkppCircuit } from "./zkpp-circuit.js";
import {
  operationContext,
  policyOf,
  transcriptContext,
  zkppInstances,
} from "./statement.js";
type Affine = NonNullable<Point>;

/** The circuit's domain size, 2^k rows (`sid_pake_core::circuit::ZKPP_K`). */
const ZKPP_K = 11;

/** Stored shapes unused this long are removed. */
const UNUSED_MS = 90 * 24 * 3600 * 1000;

const SRS_ENTRY = `srs:${ZKPP_K}`;
const shapeEntry = (policyVersion: number, historyDomains: number) =>
  `key:${policyVersion}:${historyDomains}`;

/** Everything one registration proof is made from. */
export interface ProveJob {
  /** The password bytes (UTF-8), at most MAX_PASSWORD_LEN. */
  password: Uint8Array;
  /** The OPRF blind of the registration request, below the base modulus. */
  blind: bigint;
  /** The operation's 16-byte id and the registration request the proof binds to. */
  operationId: Uint8Array;
  request: Uint8Array;
  policyVersion: number;
  /** The owner domain d, the comparison domains, the history blind and answers. */
  d: bigint;
  domains: bigint[];
  r: bigint;
  evaluations: Affine[];
}

export interface ProveResult {
  proof: Uint8Array;
  instances: bigint[];
}

/** Progress of key preparation or of a proof: a stage name and its fraction. */
export type CoreProgress = (stage: string, fraction: number) => void;

export class ProverCore {
  private srs: Promise<Srs> | null = null;
  private readonly keys = new Map<string, Promise<ProvingKey>>();
  private readonly pool: ProverPool;
  private poolReady: Promise<void> | null = null;

  private readonly store: Promise<KeyStore>;

  /**
   * `pool` defaults to the calling thread; `store` (memory by default) keeps
   * the derived key across visits, see {@link openKeyStore}.
   */
  constructor(
    pool?: ProverPool,
    private readonly rng: RandomSource = secureRandom,
    store?: Promise<KeyStore> | KeyStore,
  ) {
    this.pool = pool ?? new LocalPool();
    this.store = Promise.resolve(store ?? new MemoryKeyStore());
  }

  /**
   * The store's value of `name`, or null. A store that fails is treated as
   * empty: the key is then derived, which only costs time.
   */
  private async stored(name: string): Promise<Uint8Array | null> {
    try {
      const s = await this.store;
      const bytes = await s.get(name);
      if (bytes) await s.touch(name);
      return bytes;
    } catch {
      return null;
    }
  }

  /** Keep `bytes` under `name`; a store that fails leaves only the cache miss. */
  private async keep(name: string, bytes: Uint8Array): Promise<void> {
    try {
      await (await this.store).put(name, bytes);
    } catch {
      // Quota or blocked storage: the next visit derives the key again.
    }
  }

  /** Remove stored shapes nobody used for {@link UNUSED_MS}. */
  private async prune(): Promise<void> {
    try {
      const s = await this.store;
      const now = Date.now();
      for (const e of await s.list())
        if (e.name !== SRS_ENTRY && now - e.usedAt > UNUSED_MS)
          await s.delete(e.name);
    } catch {
      // Pruning is housekeeping; a failing store keeps its entries.
    }
  }

  private commitmentKey(onProgress?: CoreProgress): Promise<Srs> {
    this.srs ??= (async () => {
      const bytes = await this.stored(SRS_ENTRY);
      const cached = bytes && decodeSrs(bytes, ZKPP_K);
      if (cached) {
        onProgress?.("srs", 1);
        return cached;
      }
      const srs = await generateSrsOn(this.pool, ZKPP_K, (f) =>
        onProgress?.("srs", f),
      );
      await this.keep(SRS_ENTRY, encodeSrs(srs));
      return srs;
    })();
    // A failed derivation is not cached, so the next preparation retries.
    this.srs.catch(() => (this.srs = null));
    return this.srs;
  }

  /** The key's column commitments on the pool, a few columns per round for progress. */
  private async commitColumns(
    polys: bigint[][],
    onProgress?: CoreProgress,
  ): Promise<Point[]> {
    const step = Math.max(1, this.pool.lanes * 2);
    const out: Point[] = [];
    for (let s = 0; s < polys.length; s += step) {
      out.push(
        ...(await this.pool.msmMany(polys.slice(s, s + step), "lagrange")),
      );
      onProgress?.("keygen", out.length / polys.length);
    }
    return out;
  }

  /**
   * Derive (once) the key for `policyVersion` over `historyDomains`
   * comparison domains and load it into the pool.
   */
  prepare(
    policyVersion: number,
    historyDomains: number,
    onProgress?: CoreProgress,
  ): Promise<ProvingKey> {
    const id = `${policyVersion}:${historyDomains}`;
    let key = this.keys.get(id);
    if (!key) {
      key = (async () => {
        const srs = await this.commitmentKey(onProgress);
        this.poolReady ??= this.pool.init(srs);
        await this.poolReady;
        onProgress?.("keygen", 0);
        const shape = { policy: policyOf(policyVersion), historyDomains };
        const columns = keygenColumns(zkppCircuit(shape), ZKPP_K);
        const polys = [...columns.fixed, ...columns.sigmas];
        const digest = columnsDigest(columns);
        const entry = shapeEntry(policyVersion, historyDomains);
        const bytes = await this.stored(entry);
        let commitments =
          bytes && decodeCommitments(bytes, digest, polys.length);
        if (commitments) onProgress?.("keygen", 1);
        else {
          commitments = withDefaultBlind(
            await this.commitColumns(polys, onProgress),
            srs,
          );
          await this.keep(entry, encodeCommitments(digest, commitments));
        }
        const f = columns.fixed.length;
        const kg = keygenFinish(
          columns,
          commitments.slice(0, f),
          commitments.slice(f),
        );
        const pk = provingKey(kg, srs);
        void this.prune();
        onProgress?.("load-key", 0);
        const qpd = (1 << pk.keygen.extendedK) >> pk.keygen.k;
        await this.pool.loadKey(
          pk.id,
          { shape: pk.shape, polys: pk.polys },
          qpd,
        );
        onProgress?.("load-key", 1);
        return pk;
      })();
      // A failed preparation is not cached, so the next call retries.
      key.catch(() => this.keys.delete(id));
      this.keys.set(id, key);
    }
    return key;
  }

  async prove(job: ProveJob, onProgress?: CoreProgress): Promise<ProveResult> {
    if (job.password.length === 0) throw new Error("password cannot be empty");
    if (job.password.length > MAX_PASSWORD_LEN)
      throw new Error("password longer than the circuit holds");
    if (job.evaluations.length !== job.domains.length)
      throw new Error("history: one evaluation per comparison domain");
    const pk = await this.prepare(
      job.policyVersion,
      job.domains.length,
      onProgress,
    );
    const password = new Uint8Array(MAX_PASSWORD_LEN);
    password.set(job.password);
    const history = historyWitness(
      historyInput(job.d, job.password),
      job.r,
      job.evaluations,
    );
    const shape = {
      policy: policyOf(job.policyVersion),
      historyDomains: job.domains.length,
    };
    const instances = zkppInstances(
      job.password,
      job.blind,
      job.d,
      job.domains,
      history,
    );
    const m = Pallas.toBytes({ x: instances[0], y: instances[1] });
    // The proof states M = blind·H(P); it must be the request it is bound to.
    if (m.some((b, i) => b !== job.request[i]) || job.request.length !== 32)
      throw new Error("the request is not this password under this blind");
    const proof = await createProof(
      pk,
      zkppCircuit(shape, {
        password,
        passwordLen: job.password.length,
        blind: job.blind,
        d: job.d,
        domains: job.domains,
        history,
        // The key is derived with this same empty filter, as the verifier's
        // is: the proof states no breach screening. A populated filter
        // changes the verifying key and is not part of this package.
        breachBits: new Array(256).fill(0),
      }),
      instances,
      this.rng,
      {
        context: [
          transcriptContext(operationContext(job.operationId, job.request)),
        ],
        pool: this.pool,
        onProgress,
      },
    );
    return { proof, instances };
  }

  close(): void {
    this.pool.close();
  }
}
