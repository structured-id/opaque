// A prover lane on a Node worker thread: the kernel served over parentPort.
import { parentPort } from "node:worker_threads";
import { serveKernel, type LaneEndpoint } from "../../src/halo2/lanes.js";

if (!parentPort) throw new Error("node-lane runs as a worker thread");
const port = parentPort;
const endpoint: LaneEndpoint = {
  postMessage: (m) => port.postMessage(m),
  onmessage: null,
};
port.on("message", (data) => endpoint.onmessage?.({ data }));
serveKernel(endpoint);
