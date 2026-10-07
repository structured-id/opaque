// Kernel loading in a real, cross-origin-isolated browser (the delivery
// without a native kernel package). A worker whose script is not served stops
// its client instead of hanging; a registered native kernel that does not
// load gives way to the TypeScript tier before the client holds any
// operation's state, and that client works.
import { afterEach, describe, expect, it } from "vitest";
import { createTsClient } from "../src/backend-ts.js";
import { selectKernel } from "../src/capabilities.js";
import { loadZkppClient, type ZkppKernelFallback } from "../src/loader.js";
import { registerZkppKernel } from "../src/kernel.js";

const REGISTRY = Symbol.for("@structured-id/opaque/zkpp-kernel");
afterEach(() => {
  delete (globalThis as Record<symbol, unknown>)[REGISTRY];
});

/** A module worker whose script the server does not have. */
const unserved = () =>
  new Worker(new URL("./no-such-worker.js", import.meta.url), {
    type: "module",
  });

describe("loading in a browser", () => {
  it("the page is cross-origin isolated, so a native kernel would be chosen", () => {
    expect(globalThis.crossOriginIsolated).toBe(true);
    registerZkppKernel(async () => {
      throw new Error("unused");
    });
    expect(selectKernel()).toBe("wasm-simd-threaded");
  });

  it("a prover worker whose script is not served stops the client", async () => {
    const client = createTsClient("ts-threaded", {
      lanes: 1,
      spawnProver: unserved,
      spawnLane: unserved,
    });
    await expect(client.prepare(1, 1)).rejects.toThrow(/worker failed/);
    expect(client.stopped).toBe(true);
    await expect(client.prepare(1, 1)).rejects.toThrow(/worker failed/);
  }, 30_000);

  it("a native kernel that does not load gives way to a working TypeScript client", async () => {
    const unreachable = new Error("kernel artifacts unreachable");
    registerZkppKernel(async () => {
      throw unreachable;
    });
    const fallbacks: ZkppKernelFallback[] = [];
    const client = await loadZkppClient({
      onFallback: (f) => fallbacks.push(f),
    });
    expect(fallbacks).toEqual([
      { from: "wasm-simd-threaded", to: "ts-threaded", reason: unreachable },
    ]);
    expect(client.kernel).toBe("ts-threaded");
    expect(client.stopped).toBe(false);
    const start = await client.registrationStart("Str0ngP@ssword!");
    expect(start.request.length).toBeGreaterThan(0);
  }, 30_000);
});
