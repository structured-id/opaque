// A pool lane whose worker reported an error answers nothing again: its
// pending and later calls fail at once instead of waiting for a reply.
import { describe, expect, it } from "vitest";
import { WorkerPool, type LaneWorker } from "../src/halo2/lanes.js";

class FakeLane implements LaneWorker {
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  posted: unknown[] = [];
  postMessage(message: unknown): void {
    this.posted.push(message);
  }
  terminate(): void {}
}

describe("WorkerPool lane", () => {
  it("fails pending and later calls once its worker reported an error", async () => {
    const lane = new FakeLane();
    const pool = new WorkerPool(() => lane, 1);
    const pending = pool.loadKey("k", {} as never, 1);
    lane.onerror?.(new Error("lane crashed"));
    await expect(pending).rejects.toThrow(/lane crashed/);
    const sent = lane.posted.length;
    await expect(pool.loadKey("k", {} as never, 1)).rejects.toThrow(
      /lane crashed/,
    );
    expect(lane.posted).toHaveLength(sent);
  });
});
