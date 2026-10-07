// Kernel selection and loading: a WASM tier only where a native kernel is
// registered and the platform runs it, otherwise the package's TS tiers.
import { afterEach, describe, it, expect } from "vitest";
import { selectKernel, type Capabilities } from "../src/capabilities.js";
import { loadZkppClient, ZkppUnavailableError } from "../src/loader.js";
import type { ZkppClient } from "../src/loader.js";
import {
  registerZkppKernel,
  registeredZkppKernel,
  type ZkppKernelFactory,
} from "../src/kernel.js";

const cap = (
  wasm: boolean,
  simd128: boolean,
  threads: boolean,
  workers = true,
): Capabilities => ({ wasm, simd128, threads, workers });

const REGISTRY = Symbol.for("@structured-id/opaque/zkpp-kernel");

afterEach(() => {
  delete (globalThis as Record<symbol, unknown>)[REGISTRY];
});

describe("ZKPP kernel selection priority", () => {
  it("with a native kernel prefers wasm-simd-threaded, falls through to pure ts", () => {
    expect(selectKernel(cap(true, true, true), true)).toBe(
      "wasm-simd-threaded",
    );
    expect(selectKernel(cap(true, false, true), true)).toBe("wasm-threaded");
    expect(selectKernel(cap(false, false, false), true)).toBe("ts-threaded");
    expect(selectKernel(cap(false, false, false, false), true)).toBe("ts");
    expect(selectKernel(cap(false, true, true), true)).toBe("ts-threaded"); // no wasm
  });

  // The native artifacts import shared memory, which a page without
  // cross-origin isolation cannot create: without threads no WASM kernel loads.
  it("never picks a WASM kernel without shared-memory threads", () => {
    expect(selectKernel(cap(true, true, false), true)).toBe("ts-threaded");
    expect(selectKernel(cap(true, false, false), true)).toBe("ts-threaded");
    expect(selectKernel(cap(true, true, false, false), true)).toBe("ts");
  });

  // The package ships no WASM: a capable platform without a registered
  // native kernel still gets the TS tiers.
  it("never picks a WASM kernel when none is registered", () => {
    expect(selectKernel(cap(true, true, true), false)).toBe("ts-threaded");
    expect(selectKernel(cap(true, true, true, false), false)).toBe("ts");
    expect(registeredZkppKernel()).toBeUndefined();
    expect(selectKernel(cap(true, true, true))).toBe("ts-threaded");
  });

  it("defaults to the registry: a registered kernel makes WASM tiers selectable", () => {
    registerZkppKernel(async () => ({}) as ZkppClient);
    expect(selectKernel(cap(true, true, true))).toBe("wasm-simd-threaded");
  });
});

describe("ZKPP kernel registry", () => {
  it("loads a WASM tier through the registered kernel, passing the tier", async () => {
    const seen: string[] = [];
    const client = { kernel: "wasm-threaded" } as ZkppClient;
    const factory: ZkppKernelFactory = async (k) => {
      seen.push(k);
      return client;
    };
    registerZkppKernel(factory);
    await expect(loadZkppClient({ kernel: "wasm-threaded" })).resolves.toBe(
      client,
    );
    expect(seen).toEqual(["wasm-threaded"]);
  });

  it("refuses a WASM tier when no native kernel is registered", async () => {
    await expect(
      loadZkppClient({ kernel: "wasm-simd-threaded" }),
    ).rejects.toThrow(/needs a registered native kernel/);
  });
});

describe("ZKPP kernel load fallback", () => {
  const unreachable = new Error("kernel artifact unreachable");
  const failing: ZkppKernelFactory = async () => {
    throw unreachable;
  };

  // The selected native kernel never loaded (artifact unreachable, compile
  // failure): it is unavailable, so the loader picks the TypeScript tier
  // before anything is proved and says why.
  it("picks the TypeScript tier when the selected native kernel does not load", async () => {
    registerZkppKernel(failing);
    const fallbacks: unknown[] = [];
    const client = await loadZkppClient({
      capabilities: cap(true, true, true),
      onFallback: (f) => fallbacks.push(f),
    });
    expect(client.kernel).toBe("ts-threaded");
    expect(fallbacks).toEqual([
      { from: "wasm-simd-threaded", to: "ts-threaded", reason: unreachable },
    ]);
  });

  it("says why in the log when nobody listens", async () => {
    registerZkppKernel(failing);
    const warned: unknown[][] = [];
    const warn = console.warn;
    console.warn = (...args: unknown[]) => warned.push(args);
    try {
      const client = await loadZkppClient({
        capabilities: cap(true, false, true, false),
      });
      expect(client.kernel).toBe("ts");
    } finally {
      console.warn = warn;
    }
    expect(warned).toHaveLength(1);
    expect(String(warned[0]?.[0])).toContain("wasm-threaded");
    expect(warned[0]).toContain(unreachable);
  });

  // An explicitly requested kernel is not swapped for another one.
  it("does not replace an explicitly requested kernel", async () => {
    registerZkppKernel(failing);
    await expect(loadZkppClient({ kernel: "wasm-threaded" })).rejects.toBe(
      unreachable,
    );
  });

  // A bundler may duplicate this package; the registry lives on globalThis
  // under a Symbol.for key, so every copy sees one registration.
  it("keeps the registration on a global symbol shared by every copy", () => {
    const factory: ZkppKernelFactory = async () => ({}) as ZkppClient;
    registerZkppKernel(factory);
    expect((globalThis as Record<symbol, unknown>)[REGISTRY]).toBe(factory);
  });

  it("a later registration replaces an earlier one", () => {
    const first: ZkppKernelFactory = async () => ({}) as ZkppClient;
    const second: ZkppKernelFactory = async () => ({}) as ZkppClient;
    registerZkppKernel(first);
    registerZkppKernel(second);
    expect(registeredZkppKernel()).toBe(second);
  });

  // Node without a native kernel: the default load is this package's own
  // TypeScript client on the calling thread (Node has no Web Workers); asking
  // for a WASM tier with none registered is refused.
  it("loads the TypeScript client and refuses an unregistered WASM tier", async () => {
    delete (globalThis as Record<symbol, unknown>)[REGISTRY];
    const client = await loadZkppClient();
    expect(client.kernel).toBe("ts");
    expect(typeof client.prepare).toBe("function");
    await expect(
      loadZkppClient({ kernel: "wasm-simd-threaded" }),
    ).rejects.toBeInstanceOf(ZkppUnavailableError);
  });
});
