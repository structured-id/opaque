/**
 * SimpleFloorPlanner region packing (halo2_proofs single_pass.rs): each region is
 * placed at the earliest row where all of its columns are free, i.e.
 *   region_start = max over the region's columns of that column's current height;
 * afterwards every used column's height becomes region_start + row_count.
 */
export interface RegionShape {
  columns: string[];
  rowCount: number;
}

export function packRegions(regions: RegionShape[]): number[] {
  const heights = new Map<string, number>();
  const starts: number[] = [];
  for (const r of regions) {
    let start = 0;
    for (const c of r.columns) start = Math.max(start, heights.get(c) ?? 0);
    starts.push(start);
    for (const c of r.columns) heights.set(c, start + r.rowCount);
  }
  return starts;
}
