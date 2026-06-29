// Real-browser (Chromium via Playwright) verification of the Web Worker pool:
// the embarrassingly-parallel coset FFTs (the prover's heaviest stage) must
// produce byte-identical output whether run inline or across a Web Worker pool,
// and the pool must actually parallelize (speedup > 1 on a multi-core machine).
// Node cannot exercise this (no `Worker` global → inline fallback), so it lives
// in a browser-mode test.
import { describe, it, expect } from 'vitest';
import { coeffToExtended, lagrangeToCoeff } from '../src/domain.js';
import { parallelMap, hwConcurrency, workersAvailable } from '../src/worker-pool.js';

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
