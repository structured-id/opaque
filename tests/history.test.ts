// Private-history client against the Rust reference: for each vector
// (fixtures/history-vectors.json, from the sid-pake-core `history_vectors`
// example) the domains, the history input, its canonical point, the blinded
// request, the evaluator proof check and the tag must equal the Rust values.
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { Pallas } from "../src/curve.js";
import { Fp, Fq } from "../src/field.js";
import {
  blindRequest,
  canonicalPoint,
  domainElement,
  finalizeTag,
  historyInput,
  verifyEvaluation,
} from "../src/history.js";

interface Vector {
  owner: string;
  password: string;
  ownerDomain: string;
  comparisonDomain: string;
  u: string;
  h: string;
  offset: number;
  blind: string;
  blinded: string;
  publicKey: string;
  operationId: string;
  evaluated: string;
  challenge: string;
  response: string;
  tag: string;
}

const vectors: Vector[] = JSON.parse(
  readFileSync(
    new URL("./fixtures/history-vectors.json", import.meta.url),
    "utf8",
  ),
);
const unhex = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/.{2}/g) ?? [], (b) => parseInt(b, 16));
const hex = (b: Uint8Array): string =>
  [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
const utf8 = (s: string) => new TextEncoder().encode(s);

describe("private history matches the Rust reference", () => {
  vectors.forEach((v, i) => {
    it(`vector ${i}`, () => {
      const d = domainElement(utf8("SID-HISTORY-INPUT-v1"), [
        utf8("test-installation"),
        unhex(v.owner),
      ]);
      expect(hex(Fp.toBytes(d))).toBe(v.ownerDomain);
      const c = domainElement(utf8("SID-HISTORY-TAG-v1"), [
        utf8("epoch-1"),
        utf8("format-1"),
      ]);
      expect(hex(Fp.toBytes(c))).toBe(v.comparisonDomain);

      const u = historyInput(d, unhex(v.password));
      expect(hex(Fp.toBytes(u))).toBe(v.u);
      const { point, offset } = canonicalPoint(u);
      expect(hex(Pallas.toBytes(point))).toBe(v.h);
      expect(Number(offset)).toBe(v.offset);
      expect(point.y & 1n).toBe(0n);

      const r = Fp.fromBytes(unhex(v.blind));
      const b = blindRequest(u, r);
      expect(hex(Pallas.toBytes(b))).toBe(v.blinded);

      const pk = Pallas.fromBytes(unhex(v.publicKey));
      const z = Pallas.fromBytes(unhex(v.evaluated));
      const proof = {
        c: Fq.fromBytes(unhex(v.challenge)),
        s: Fq.fromBytes(unhex(v.response)),
      };
      const op = unhex(v.operationId);
      expect(verifyEvaluation(pk, b, z, op, proof)).toBe(true);
      // Bound to the operation, the key and the answer.
      expect(
        verifyEvaluation(
          pk,
          b,
          z,
          op.map((x) => x ^ 1),
          proof,
        ),
      ).toBe(false);
      expect(
        verifyEvaluation(Pallas.add(pk, Pallas.GENERATOR), b, z, op, proof),
      ).toBe(false);
      expect(
        verifyEvaluation(pk, b, Pallas.add(z, Pallas.GENERATOR), op, proof),
      ).toBe(false);

      expect(hex(Fp.toBytes(finalizeTag(c, u, r, z)))).toBe(v.tag);
    });
  });

  it("refuses a password longer than the circuit holds", () => {
    expect(() => historyInput(1n, new Uint8Array(129))).toThrow("longer");
  });
});
