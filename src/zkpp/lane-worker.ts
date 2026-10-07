/**
 * A prover lane: serves the kernel on the MessagePort it is handed, so the
 * prover worker talks to it directly.
 */
import { serveKernel, type LaneEndpoint } from "../halo2/lanes.js";

self.onmessage = (e: MessageEvent) => {
  const port = (e.data as { port?: MessagePort }).port;
  if (port) serveKernel(port as unknown as LaneEndpoint);
};
