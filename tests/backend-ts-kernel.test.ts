// The TypeScript client asks the prover host for the execution its kernel
// names: `ts` proves on the calling thread even where Web Workers exist (a
// page whose CSP forbids worker scripts selects it for that reason), while
// `ts-threaded` keeps the caller's worker options.
import { describe, expect, it, vi } from "vitest";

const createProver = vi.fn(() => ({
  prepare: async () => {},
  prove: async () => ({ proof: new Uint8Array(), instances: [] }),
  close: () => {},
  stopped: false,
}));
vi.mock("../src/zkpp/prover-host.js", () => ({ createProver }));

const { createTsClient } = await import("../src/backend-ts.js");

describe("TypeScript client kernel", () => {
  it("proves on the calling thread on the single-thread kernel", async () => {
    createProver.mockClear();
    await createTsClient("ts").prepare(1, 1);
    expect(createProver).toHaveBeenCalledWith({ local: true });
  });

  it("passes the worker options on the threaded kernel", async () => {
    createProver.mockClear();
    const opts = { lanes: 3 };
    await createTsClient("ts-threaded", opts).prepare(1, 1);
    expect(createProver).toHaveBeenCalledWith(opts);
  });
});
