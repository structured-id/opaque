import { describe, it, expect } from "vitest";
import { detectCapabilities, selectKernel } from "../src/capabilities.js";

describe("ZKPP kernel auto-selection", () => {
  it("detects WASM + SIMD128 in the test runtime (Node)", () => {
    const c = detectCapabilities();
    expect(c.wasm).toBe(true);
    expect(c.simd128).toBe(true); // Node ≥16 supports WASM SIMD
  });

  // Node has SharedArrayBuffer but no Web Workers, which the WASM artifacts
  // spawn for their thread pool; its worker_threads serve the pure-TS pool,
  // so the threaded TS tier is the best one here.
  it("selects the threaded TS tier in Node", () => {
    const c = detectCapabilities();
    expect(c.threads).toBe(false);
    expect(c.workers).toBe(true);
    expect(selectKernel()).toBe("ts-threaded");
  });
});
