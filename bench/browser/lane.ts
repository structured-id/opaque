// A prover lane in a Web Worker. It serves the kernel on the MessagePort it
// is handed, so the orchestrator talks to it directly and no message passes
// through the page's main thread (which a background tab throttles).
import { serveKernel, type LaneEndpoint } from "../../src/halo2/lanes.js";

self.onmessage = (e: MessageEvent) => {
  const port = (e.data as { port?: MessagePort }).port;
  if (port) serveKernel(port as unknown as LaneEndpoint);
};
