/**
 * The prover worker: a {@link ProverCore} over the lanes whose ports the host
 * hands it. Lanes and this worker talk port to port, so a proof never waits
 * on the page's main thread.
 */
import { WorkerPool, type LaneWorker } from "../halo2/lanes.js";
import { secureRandom } from "../random.js";
import { openKeyStore } from "./key-store.js";
import { ProverCore } from "./prover-core.js";
import type { HostMessage, WorkerMessage } from "./protocol.js";

const reply = (m: WorkerMessage) => postMessage(m);
let core: ProverCore | null = null;
let pool: WorkerPool | null = null;

function lanePort(port: MessagePort): LaneWorker {
  const lane: LaneWorker = {
    postMessage: (m) => port.postMessage(m),
    onmessage: null,
    terminate: () => port.close(),
  };
  port.onmessage = (e) => lane.onmessage?.(e);
  return lane;
}

async function handle(m: HostMessage): Promise<void> {
  if (m.t === "init") {
    let next = 0;
    pool =
      m.ports.length > 0
        ? new WorkerPool(() => lanePort(m.ports[next++]), m.ports.length)
        : null;
    // The derived key persists across visits where the worker can open IndexedDB.
    core = new ProverCore(pool ?? undefined, secureRandom, openKeyStore());
    return;
  }
  if (m.t === "active") {
    pool?.setActive(m.lanes);
    return;
  }
  const c = core;
  if (!c) throw new Error("prover worker used before init");
  const progress = (stage: string, fraction: number) =>
    reply({ t: "progress", id: m.id, stage, fraction });
  try {
    if (m.t === "prepare") {
      await c.prepare(m.policyVersion, m.historyDomains, progress);
      reply({ t: "done", id: m.id, result: null });
    } else {
      reply({ t: "done", id: m.id, result: await c.prove(m.job, progress) });
    }
  } catch (err) {
    reply({
      t: "error",
      id: m.id,
      message: err instanceof Error ? err.message : String(err),
    });
  }
}

self.onmessage = (e: MessageEvent) => void handle(e.data as HostMessage);
