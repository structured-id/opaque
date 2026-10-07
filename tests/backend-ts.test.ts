// The TypeScript client through the public loader: a password operation end
// to end (OPAQUE start, history request, evaluation, proof) whose proof states
// the request it is bound to; an evaluator answer with a forged proof is
// refused before proving; a password longer than the circuit has neither a
// history request nor a proof. That the proof verifies is checked by the
// Rust verifier (bench/client-proofs.ts, sid example verify_proofs).
import { describe, it, expect, beforeAll } from "vitest";
import { loadZkppClient, type ZkppClient } from "../src/index.js";
import { Pallas } from "../src/curve.js";
import { Fp } from "../src/field.js";
import { installPassword, testEvaluator } from "./history-evaluator.js";

let client: ZkppClient;

beforeAll(async () => {
  client = await loadZkppClient({ kernel: "ts" });
  await client.prepare(1, 1);
}, 600000);

describe("TypeScript ZKPP client", () => {
  it("proves a password operation bound to its request", async () => {
    const stages: number[] = [];
    const { start, request, proof } = await installPassword(
      client,
      "Str0ngP@ssword!",
      testEvaluator(1),
      (p) => stages.push(p.fraction),
    );
    expect(request).not.toBeNull();
    expect(proof).not.toBeNull();
    const instances = proof!.instances.map((b) => Fp.fromBytes(b));
    expect(instances).toHaveLength(9);
    // M, the first two instances, is the OPAQUE request itself.
    expect(Pallas.toBytes({ x: instances[0], y: instances[1] })).toEqual(
      start.request,
    );
    // B is the history request the evaluator answered.
    expect(Pallas.toBytes({ x: instances[4], y: instances[5] })).toEqual(
      request!.blinded,
    );
    expect(stages.at(-1)).toBe(1);
    for (let i = 1; i < stages.length; i++)
      expect(stages[i]).toBeGreaterThanOrEqual(stages[i - 1]);
  }, 600000);

  it("refuses an evaluation whose proof does not verify", async () => {
    const evaluator = testEvaluator(1);
    const password = "Str0ngP@ssword!";
    const start = await client.registrationStart(password);
    const request = await client.historyRequest(
      password,
      evaluator.context.ownerDomain,
    );
    const evaluations = evaluator.evaluate(request!.blinded);
    evaluations[0].proof.response = Fp.toBytes(12345n);
    await expect(
      client.prove(password, start, {
        context: evaluator.context,
        history: { request: request!, evaluations },
      }),
    ).rejects.toThrow("does not verify");
  });

  it("has nothing to prove for a password longer than the circuit", async () => {
    const long = "Aa1" + "x".repeat(130);
    const evaluator = testEvaluator(1);
    expect(
      await client.historyRequest(long, evaluator.context.ownerDomain),
    ).toBeNull();
    const start = await client.registrationStart(long);
    expect(
      await client.prove(long, start, {
        context: evaluator.context,
        history: null,
      }),
    ).toBeNull();
  });
});
