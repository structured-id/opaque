// The page side of the TypeScript prover with its workers. A prover or lane
// worker that stops (its script not served or failing, an uncaught error, an
// unreadable message) answers nothing again: every pending and later call
// must fail at once and the prover must say it stopped, or the page waits
// forever on the next operation.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createProver } from "../src/zkpp/prover-host.js";
import { createTsClient } from "../src/backend-ts.js";

/** A worker the test drives by hand. */
class FakeWorker {
  onmessage: ((e: MessageEvent) => void) | null = null;
  onerror: ((e: ErrorEvent) => void) | null = null;
  onmessageerror: ((e: MessageEvent) => void) | null = null;
  posted: unknown[] = [];
  terminated = false;
  postMessage(message: unknown): void {
    this.posted.push(message);
  }
  terminate(): void {
    this.terminated = true;
  }
}

let prover: FakeWorker;
let lanes: FakeWorker[];
const spawn = () => {
  prover = new FakeWorker();
  lanes = [];
  return createProver({
    lanes: 2,
    spawnProver: () => prover as unknown as Worker,
    spawnLane: () => {
      const lane = new FakeWorker();
      lanes.push(lane);
      return lane as unknown as Worker;
    },
  });
};

// The host takes the worker path only where Web Workers exist.
const realWorker = (globalThis as { Worker?: unknown }).Worker;
beforeEach(() => {
  (globalThis as { Worker?: unknown }).Worker = FakeWorker;
});
afterEach(() => {
  (globalThis as { Worker?: unknown }).Worker = realWorker;
});

describe("TypeScript prover host", () => {
  it("fails a pending call and every later one when the prover worker stops", async () => {
    const host = spawn();
    const pending = host.prepare(1, 1);
    prover.onerror?.({ message: "prover crashed" } as ErrorEvent);
    await expect(pending).rejects.toThrow(/prover crashed/);
    expect(host.stopped).toBe(true);
    const sent = prover.posted.length;
    await expect(host.prepare(1, 1)).rejects.toThrow(/prover crashed/);
    expect(prover.posted).toHaveLength(sent);
  });

  // A lane's worker is the page's; the prover worker only holds its port and
  // never hears of its failure. The host does, and stops the whole prover.
  it("stops the prover when a lane worker stops", async () => {
    const host = spawn();
    const pending = host.prepare(1, 1);
    lanes[1]?.onerror?.({ message: "lane crashed" } as ErrorEvent);
    await expect(pending).rejects.toThrow(/lane crashed/);
    expect(host.stopped).toBe(true);
    expect(prover.terminated).toBe(true);
    expect(lanes.every((l) => l.terminated)).toBe(true);
  });

  it("stops on a message it cannot read", async () => {
    const host = spawn();
    const pending = host.prepare(1, 1);
    prover.onmessageerror?.({} as MessageEvent);
    await expect(pending).rejects.toThrow(/could not be read/);
    expect(host.stopped).toBe(true);
  });

  it("is not stopped while it answers", () => {
    expect(spawn().stopped).toBe(false);
  });
});

describe("TypeScript client over a stopped prover", () => {
  // The client says it stopped, so the application loads a new one for the
  // next operation instead of failing every one after.
  it("reports stopped once its prover's worker stopped", async () => {
    const client = createTsClient("ts-threaded", {
      lanes: 1,
      spawnProver: () => (prover = new FakeWorker()) as unknown as Worker,
      spawnLane: () => new FakeWorker() as unknown as Worker,
    });
    expect(client.stopped).toBe(false);
    const preparing = client.prepare(1, 1);
    prover.onerror?.({ message: "prover crashed" } as ErrorEvent);
    await expect(preparing).rejects.toThrow(/prover crashed/);
    expect(client.stopped).toBe(true);
  });
});
