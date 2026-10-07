import { describe, it, expect } from "vitest";
import { detectCapabilities, selectKernel } from "../src/capabilities.js";

describe("ZKPP kernel auto-selection", () => {
  it("detects WASM + SIMD128 in the test runtime (Node)", () => {
    const c = detectCapabilities();
    expect(c.wasm).toBe(true);
    expect(c.simd128).toBe(true); // Node ≥16 supports WASM SIMD
  });

  // Node has SharedArrayBuffer but no Web Workers, which both the WASM
  // artifacts and the TS prover pool start. The prover then runs on the
  // calling thread, so the kernel must say so: reporting the threaded tier
  // there hid a proof blocking the event loop behind a "threaded" label.
  it("selects the single-thread TS tier in Node", () => {
    const c = detectCapabilities();
    expect(c.threads).toBe(false);
    expect(c.workers).toBe(false);
    expect(selectKernel()).toBe("ts");
  });
});
