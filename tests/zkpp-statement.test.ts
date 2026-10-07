// What a proof states and is bound to, against the Rust reference vector
// (sid-pake-core `proof_vectors`): the nine public instances computed from the
// password, OPRF blind, domains and history answer, and the transcript scalar
// of the operation context over the registration request M.
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { Pallas, type Point } from "../src/curve.js";
import { Fp } from "../src/field.js";
import { historyInput } from "../src/history.js";
import { historyWitness } from "../src/zkpp/circuit.js";
import {
  operationContext,
  policyOf,
  transcriptContext,
  zkppInstances,
} from "../src/zkpp/statement.js";

const v = JSON.parse(
  readFileSync(
    new URL("./fixtures/proof-vector.json", import.meta.url),
    "utf8",
  ),
);
const unhex = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/.{2}/g) ?? [], (b) => parseInt(b, 16));
const fe = (h: string) => Fp.fromBytes(unhex(h));

describe("proof statement", () => {
  const pw = unhex(v.password);
  const blind = fe(v.blind);
  const d = fe(v.d);
  const history = historyWitness(historyInput(d, pw), fe(v.r), [
    Pallas.fromBytes(unhex(v.z)) as NonNullable<Point>,
  ]);

  it("computes the reference instances", () => {
    expect(zkppInstances(pw, blind, d, [fe(v.c)], history)).toEqual(
      (v.instances as string[]).map(fe),
    );
  });

  it("binds to the operation and its request like the reference", () => {
    const [mx, my] = zkppInstances(pw, blind, d, [fe(v.c)], history);
    const request = Pallas.toBytes({ x: mx, y: my });
    expect(
      transcriptContext(operationContext(unhex(v.operationId), request)),
    ).toBe(fe(v.context));
  });

  it("refuses a malformed operation id and an unknown policy", () => {
    expect(() =>
      operationContext(new Uint8Array(15), new Uint8Array(32)),
    ).toThrow("16 bytes");
    expect(() => policyOf(2)).toThrow("not found");
    expect(policyOf(1).minLength).toBe(8);
  });
});
