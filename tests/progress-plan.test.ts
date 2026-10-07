// The combined progress bar: segment widths follow the expected step times
// with a floor for short steps; the bar follows step reports and, between
// them, elapsed time, never reaching a step's end before the step says so
// and never moving back; finishing moves the estimates toward what was
// measured (exponential moving average).
import { describe, it, expect } from "vitest";
import { ProgressPlan } from "../src/progress.js";

let clock = 0;
const now = () => clock;

describe("ProgressPlan", () => {
  it("sizes segments by expected time, with a floor for short steps", () => {
    const plan = new ProgressPlan(["keygen", "witness", "quotient", "ipa"], {
      estimates: { keygen: 43000, witness: 10, quotient: 2000, ipa: 8000 },
      minShare: 0.02,
      now,
    });
    const w = plan.segments.map((s) => Number(s.width.toFixed(3)));
    // witness is far below 2%, so it gets the floor; the rest share 98%
    // in proportion 43 : 2 : 8.
    expect(w[1]).toBe(0.02);
    expect(w[0]).toBeCloseTo((0.98 * 43) / 53, 3);
    expect(w[2]).toBeCloseTo((0.98 * 2) / 53, 3);
    expect(w[3]).toBeCloseTo((0.98 * 8) / 53, 3);
    expect(plan.segments.reduce((s, x) => s + x.width, 0)).toBeCloseTo(1, 9);
    plan.segments.forEach((s, i) =>
      i === 0
        ? expect(s.start).toBe(0)
        : expect(s.start).toBeCloseTo(
            plan.segments[i - 1].start + plan.segments[i - 1].width,
            9,
          ),
    );
  });

  it("moves with reports and time but stops short of an unfinished step", () => {
    clock = 0;
    const plan = new ProgressPlan(["srs", "keygen"], {
      estimates: { srs: 1000, keygen: 1000 },
      now,
    });
    expect(plan.fraction()).toBe(0);
    plan.report("srs", 0);
    clock = 500;
    expect(plan.fraction()).toBeCloseTo(0.25, 6); // half of the first half
    clock = 5000; // far over the estimate: held at 95% of the segment
    expect(plan.fraction()).toBeCloseTo(0.475, 6);
    plan.report("srs", 1);
    expect(plan.fraction()).toBeCloseTo(0.5, 6);
    plan.report("keygen", 0.2);
    expect(plan.fraction()).toBeCloseTo(0.6, 6);
    // a lower report never moves the bar back
    plan.report("keygen", 0.1);
    expect(plan.fraction()).toBeCloseTo(0.6, 6);
    plan.finish();
    expect(plan.fraction()).toBe(1);
    expect(plan.step()).toBe("keygen");
  });

  it("moves the estimates toward the measured times", () => {
    clock = 0;
    const plan = new ProgressPlan(["srs", "keygen"], {
      estimates: { srs: 1000, keygen: 1000 },
      alpha: 0.5,
      now,
    });
    plan.report("srs", 0);
    clock = 3000;
    plan.report("keygen", 0);
    clock = 3500;
    const next = plan.finish();
    expect(next.srs).toBe(2000); // 1000·0.5 + 3000·0.5
    expect(next.keygen).toBe(750); // 1000·0.5 + 500·0.5
    expect(next.ipa).toBeGreaterThan(0); // untouched steps keep their default
  });

  it("refuses an empty plan", () => {
    expect(() => new ProgressPlan([])).toThrow("needs steps");
  });
});
