// Registration proofs made through the public client API, one JSON line each
// for a reference verifier: `yarn tsx bench/client-proofs.ts <out.jsonl>
// [kernel]`. The default kernel is `ts` (the calling thread).
import { writeFileSync } from "fs";
import { loadZkppClient, type Kernel } from "../src/index.js";
import { installPassword, testEvaluator } from "../tests/history-evaluator.js";

const out = process.argv[2];
if (!out) throw new Error("usage: client-proofs.ts <out.jsonl> [kernel]");
const kernel = (process.argv[3] ?? "ts") as Kernel;
const hex = (b: Uint8Array) =>
  [...b].map((v) => v.toString(16).padStart(2, "0")).join("");

const client = await loadZkppClient({ kernel });
let t0 = performance.now();
await client.prepare(1, 1);
console.log(`prepare ${(performance.now() - t0).toFixed(0)} ms`);
const lines: string[] = [];
for (const [i, password] of ["Str0ngP@ssword!", "An0ther-Passw0rd"].entries()) {
  const evaluator = testEvaluator(1);
  t0 = performance.now();
  const { start, proof } = await installPassword(client, password, evaluator);
  console.log(`proof ${i}: ${(performance.now() - t0).toFixed(0)} ms`);
  if (!proof) throw new Error("no proof");
  lines.push(
    JSON.stringify({
      label: `node-${kernel}-${i}`,
      policyVersion: 1,
      operationId: hex(evaluator.context.operationId),
      request: hex(start.request),
      proof: hex(proof.proof),
      instances: proof.instances.map(hex),
    }),
  );
}
writeFileSync(out, lines.join("\n") + "\n");
console.log(`wrote ${lines.length} proofs to ${out}`);
