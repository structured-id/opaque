// A WorkerPool on Node worker threads, for benches and tests.
import { Worker } from "node:worker_threads";
import { WorkerPool, type LaneWorker } from "../../src/halo2/lanes.js";

export function nodePool(lanes: number): WorkerPool {
  const spawn = (): LaneWorker => {
    const w = new Worker(new URL("./node-lane.ts", import.meta.url), {
      execArgv: ["--import", "tsx"],
    });
    const lane: LaneWorker = {
      postMessage: (m) => w.postMessage(m),
      onmessage: null,
      onerror: null,
      terminate: () => void w.terminate(),
    };
    w.on("message", (data) => lane.onmessage?.({ data }));
    w.on("error", (e) => lane.onerror?.(e));
    return lane;
  };
  return new WorkerPool(spawn, lanes);
}
