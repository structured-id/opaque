// Browser bench of the TypeScript prover. The page only wires workers: it
// starts the orchestrator and the lanes and hands each lane's MessagePort to
// the orchestrator, so proving never waits on the page's main thread (which a
// background tab throttles). Query: ?dev=<tag>&lanes=<n>&rounds=<n>&single=1.
const q = new URLSearchParams(location.search);
const lanes = Number(q.get("lanes") ?? navigator.hardwareConcurrency ?? 4);
const out = document.getElementById("log") as HTMLElement;

const orchestrator = new Worker(new URL("./orchestrator.js", import.meta.url), {
  type: "module",
});
orchestrator.onmessage = (e) => {
  out.textContent += `${e.data} [page ${document.visibilityState}]\n`;
};
const ports = Array.from({ length: lanes }, () => {
  const lane = new Worker(new URL("./lane.js", import.meta.url), {
    type: "module",
  });
  const channel = new MessageChannel();
  lane.postMessage({ port: channel.port1 }, [channel.port1]);
  return channel.port2;
});
orchestrator.postMessage(
  {
    dev: q.get("dev") ?? "unknown",
    rounds: Number(q.get("rounds") ?? 3),
    single: q.get("single") === "1",
    ports,
  },
  ports,
);
