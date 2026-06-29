// Real-browser (Chromium via Playwright) verification of the Web Worker pool:
// the embarrassingly-parallel coset FFTs (the prover's heaviest stage) must
// produce byte-identical output whether run inline or across a Web Worker pool,
// and the pool must actually parallelize (speedup > 1 on a multi-core machine).
// Node cannot exercise this (no `Worker` global → inline fallback), so it lives
// in a browser-mode test.
import { describe, it, expect } from 'vitest';
import { coeffToExtended, lagrangeToCoeff } from '../src/domain.js';
import { Vesta } from '../src/curve.js';
import { parallelMap, hwConcurrency, workersAvailable, WorkerPool } from '../src/worker-pool.js';

type Pt = { x: bigint; y: bigint };

const K = 11;
const EXTK = 14;
const N = 2048;
const toCos = (col: bigint[]): bigint[] => coeffToExtended(lagrangeToCoeff(col, K), EXTK);

// Same worker module + message shape the prover uses for cosets.
const cosetSpec = {
  url: new URL('../src/coset-worker.ts', import.meta.url),
  toMessage: (p: bigint[]): unknown => p,
  fromMessage: (m: unknown): bigint[] => m as bigint[],
};

// Deterministic synthetic advice columns (we test the FFT pipeline + worker
// transport, not a specific witness).
const makeCol = (c: number): bigint[] =>
  Array.from({ length: N }, (_, i) => BigInt(((i * 2654435761 + c * 40503) >>> 0) + 1));

describe('coset FFT Web Worker parallelism (real Chromium)', () => {
  it('worker pool matches inline byte-exact and parallelizes', async () => {
    expect(workersAvailable()).toBe(true); // browser exposes Worker
    const cores = hwConcurrency();
    const cols = Array.from({ length: 32 }, (_, c) => makeCol(c));

    let t = performance.now();
    const inline = cols.map(toCos);
    const tInline = performance.now() - t;

    t = performance.now();
    const par = await parallelMap(cols, toCos, cosetSpec, { maxWorkers: cores });
    const tPar = performance.now() - t;

    // byte-exact: every parallel coset equals the inline one
    let mismatched = 0;
    for (let c = 0; c < cols.length; c++) {
      if (par[c].length !== inline[c].length) {
        mismatched++;
        continue;
      }
      for (let i = 0; i < inline[c].length; i++)
        if (par[c][i] !== inline[c][i]) {
          mismatched++;
          break;
        }
    }
    const speedup = tInline / tPar;
    console.log(
      `WORKERS: cores=${cores} cols=${cols.length} inline=${tInline.toFixed(0)}ms ` +
        `workers=${tPar.toFixed(0)}ms speedup=${speedup.toFixed(2)}x mismatched=${mismatched}`,
    );
    expect(mismatched).toBe(0);
    expect(par.length).toBe(cols.length);
    // On any multi-core CI the pool should beat inline; allow margin for tiny machines.
    if (cores > 1) expect(speedup).toBeGreaterThan(1);
  }, 120000);
});

describe('commit MSM Web Worker parallelism (real Chromium)', () => {
  it('worker pool (SRS init) matches inline byte-exact and parallelizes', async () => {
    const cores = hwConcurrency();
    // Synthetic SRS (incremental basis) + blinding generator.
    const G = Vesta.GENERATOR as Pt;
    const SRS = 512;
    const gL: Pt[] = [G];
    for (let i = 1; i < SRS; i++) gL.push(Vesta.add(gL[i - 1], G) as Pt);
    const w = Vesta.double(G) as Pt;
    const tasks = 24;
    const polys = Array.from({ length: tasks }, (_, c) =>
      Array.from({ length: SRS }, (_, i) => BigInt(((i * 2654435761 + c * 40503) >>> 0) + 1)),
    );
    const blinds = Array.from({ length: tasks }, (_, c) => BigInt(c + 7));
    const commit = (c: number): Pt =>
      Vesta.add(Vesta.msm(polys[c], gL), Vesta.scalarMul(blinds[c], w)) as Pt;

    let t = performance.now();
    const inline = Array.from({ length: tasks }, (_, c) => commit(c));
    const tInline = performance.now() - t;

    const spec = {
      url: new URL('../src/commit-worker.ts', import.meta.url),
      initMessage: { gL, w },
      toMessage: (c: number): unknown => ({ poly: polys[c], blind: blinds[c] }),
      fromMessage: (m: unknown): Pt => m as Pt,
    };
    t = performance.now();
    const par = await parallelMap(
      Array.from({ length: tasks }, (_, c) => c),
      commit,
      spec,
      { maxWorkers: cores },
    );
    const tPar = performance.now() - t;

    let mismatched = 0;
    for (let c = 0; c < tasks; c++)
      if (par[c].x !== inline[c].x || par[c].y !== inline[c].y) mismatched++;
    const speedup = tInline / tPar;
    console.log(
      `COMMITS: cores=${cores} tasks=${tasks} srs=${SRS} inline=${tInline.toFixed(0)}ms ` +
        `workers=${tPar.toFixed(0)}ms speedup=${speedup.toFixed(2)}x mismatched=${mismatched}`,
    );
    expect(mismatched).toBe(0);
    if (cores > 1) expect(speedup).toBeGreaterThan(1);
  }, 120000);
});

describe('persistent pool reuse vs respawn (real Chromium)', () => {
  it('one pool reused across 3 batches is no slower than respawning per batch', async () => {
    const cores = hwConcurrency();
    const cols = Array.from({ length: 16 }, (_, c) => makeCol(c));
    const url = new URL('../src/coset-worker.ts', import.meta.url);
    const toMsg = (p: bigint[]): unknown => p;
    const fromMsg = (m: unknown): bigint[] => m as bigint[];

    // respawn: 3 separate parallelMap calls (workers spawned + terminated each time)
    let t = performance.now();
    for (let s = 0; s < 3; s++)
      await parallelMap(cols, toCos, { url, toMessage: toMsg, fromMessage: fromMsg }, { maxWorkers: cores });
    const tRespawn = performance.now() - t;

    // persistent: one pool, three batches (spawn paid once)
    const pool = new WorkerPool(url, cores);
    t = performance.now();
    for (let s = 0; s < 3; s++) await pool.map(cols, toCos, toMsg, fromMsg);
    const tPool = performance.now() - t;
    pool.terminate();

    console.log(
      `POOL: respawn-3x=${tRespawn.toFixed(0)}ms persistent-3x=${tPool.toFixed(0)}ms ` +
        `gain=${(tRespawn / tPool).toFixed(2)}x`,
    );
    expect(pool.available()).toBe(true);
    if (cores > 1) expect(tPool).toBeLessThanOrEqual(tRespawn);
  }, 120000);
});
