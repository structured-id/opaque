// Progress model.
import { describe, it, expect } from "vitest";
import { ProgressTracker, type ZkppProgress } from "../src/progress.js";

describe("ZKPP progress tracker (gauge model)", () => {
  it("maps stage sub-fractions to a monotonic overall 0..1", () => {
    const seen: ZkppProgress[] = [];
    const t = new ProgressTracker((p) => seen.push(p));
    t.report("witness", 1); // 0.02
    t.report("commit-advice", 0.5); // 0.02 + 0.035
    t.report("commit-advice", 1); // 0.09
    t.report("quotient", 1); // + lookups 0.03 + permutation 0.17 + 0.52 = 0.81
    t.done(); // 1
    expect(seen.map((p) => Number(p.fraction.toFixed(2)))).toEqual([
      0.02, 0.06, 0.09, 0.81, 1,
    ]);
    // Monotonic: never decreases.
    for (let i = 1; i < seen.length; i++)
      expect(seen[i].fraction).toBeGreaterThanOrEqual(seen[i - 1].fraction);
    expect(seen[2].label).toBe("Committing columns");
  });

  it("never goes backwards even if a stage reports a lower sub", () => {
    const seen: number[] = [];
    const t = new ProgressTracker((p) => seen.push(p.fraction));
    t.report("commit-advice", 0.8);
    t.report("commit-advice", 0.3); // lower sub → clamped to previous
    expect(seen[1]).toBeGreaterThanOrEqual(seen[0]);
  });
});
