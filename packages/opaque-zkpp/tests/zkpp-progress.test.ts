// Progress model + worker-pool single-thread fallback.
import { describe, it, expect } from 'vitest';
import { ProgressTracker, type ZkppProgress } from '../src/progress.js';
import { parallelMap, workersAvailable } from '../src/worker-pool.js';

describe('ZKPP progress tracker (gauge model)', () => {
  it('maps stage sub-fractions to a monotonic overall 0..1', () => {
    const seen: ZkppProgress[] = [];
    const t = new ProgressTracker((p) => seen.push(p));
    t.report('witness', 1); // 0.03
    t.report('commit-advice', 0.5); // 0.03 + 0.18
    t.report('commit-advice', 1); // 0.39
    t.report('quotient', 1); // 0.97
    t.done(); // 1
    expect(seen.map((p) => Number(p.fraction.toFixed(2)))).toEqual([0.03, 0.21, 0.39, 0.97, 1]);
    // Monotonic: never decreases.
    for (let i = 1; i < seen.length; i++) expect(seen[i].fraction).toBeGreaterThanOrEqual(seen[i - 1].fraction);
    expect(seen[2].label).toBe('Committing columns');
  });

  it('never goes backwards even if a stage reports a lower sub', () => {
    const seen: number[] = [];
    const t = new ProgressTracker((p) => seen.push(p.fraction));
    t.report('commit-advice', 0.8);
    t.report('commit-advice', 0.3); // lower sub → clamped to previous
    expect(seen[1]).toBeGreaterThanOrEqual(seen[0]);
  });
});

describe('worker-pool parallelMap — single-thread fallback', () => {
  it('runs inline (no worker spec) preserving order + ticking progress', async () => {
    const ticks: Array<[number, number]> = [];
    const out = await parallelMap([1, 2, 3, 4], (x) => x * 10, undefined, {
      onTick: (d, t) => ticks.push([d, t]),
    });
    expect(out).toEqual([10, 20, 30, 40]);
    expect(ticks).toEqual([[1, 4], [2, 4], [3, 4], [4, 4]]);
  });

  it('workersAvailable() returns a boolean (false in plain node → fallback path)', () => {
    expect(typeof workersAvailable()).toBe('boolean');
  });
});

import { processColumn } from '../src/zkpp-worker-kernel.js';

describe('zkpp-worker kernel (shared worker payload + inline fallback)', () => {
  it('processColumn commits a column (MSM) and FFTs it to the extended domain', () => {
    const scalars = Array.from({ length: 16 }, (_, i) => BigInt(i % 5));
    const r = processColumn({ scalars, extendedK: 7 });
    expect(r.commitment).not.toBeNull();
    expect(r.commitment!.x).toBeTypeOf('bigint');
    expect(r.ext.length).toBe(1 << 7); // extended domain size 2^extendedK
  });
});
