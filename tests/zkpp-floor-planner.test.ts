// SimpleFloorPlanner region packing interop vs halo2_proofs single_pass placement.
import { describe, it, expect } from 'vitest';
import { packRegions } from '../src/zkpp/circuit/floor-planner.js';
import regions from './fixtures/zkpp-regions.json';

describe('SimpleFloorPlanner region packing — halo2 interop', () => {
  it('reproduces region_start for all 71 ZkppCircuit regions', () => {
    const got = packRegions(regions.map((r) => ({ columns: r.columns, rowCount: r.rowCount })));
    expect(got).toEqual(regions.map((r) => r.start));
  });
});
