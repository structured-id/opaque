// End-to-end: buildAdvice (password -> witness) + createProof (witness -> proof)
// must reproduce the Rust proof byte-exact (12352 bytes). Loads circuit params from
// the /tmp dump (production bundles them); skips in CI if the dump is absent.
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { Vesta } from "../src/curve.js";
import { omegaForSize } from "../src/fft.js";
import { leHex, type Ast } from "../src/gate-eval.js";
import { buildAdvice } from "../src/circuit/witness.js";
import {
  createProof,
  type ProverParams,
  type Query,
} from "../src/create-proof.js";
import type { PolicyParams } from "../src/circuit/gadget-a.js";

const N = 2048;
const K = 11;
const EXTN = 1 << 14;
const fromHex = (h: string) =>
  Uint8Array.from(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
const CE: PolicyParams = {
  minLength: 8,
  minUpper: 1,
  minLower: 1,
  minDigit: 1,
  minSymbol: 0,
};

describe("end-to-end createProof", () => {
  it("buildAdvice + createProof reproduce the Rust proof byte-exact (12352)", async () => {
    if (
      !existsSync("/tmp/sid_zkpp_proof.txt") ||
      !existsSync("/tmp/sid_mo.txt")
    ) {
      console.log("SKIP: no dump");
      return;
    }
    const loadL = (path: string, tag: string, nc: number): bigint[][] => {
      const c = Array.from({ length: nc }, () => Array<bigint>(N).fill(0n));
      for (const l of readFileSync(path, "utf8").split("\n")) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(\\d+):(.+)$`));
        if (m) c[+m[1]][+m[2]] = leHex(m[3]);
      }
      return c;
    };
    const loadExt = (tag: string): bigint[] => {
      const a = Array<bigint>(EXTN).fill(0n);
      for (const l of readFileSync("/tmp/sid_zkpp_pk.txt", "utf8").split(
        "\n",
      )) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(.+)$`));
        if (m) a[+m[1]] = leHex(m[2]);
      }
      return a;
    };
    const fixed = loadL("/tmp/sid_zkpp_pk.txt", "F", 55);
    const sigmas = loadL("/tmp/sid_zkpp_pk.txt", "S", 56);
    const instanceCol = Array<bigint>(N).fill(0n);
    for (const l of readFileSync("/tmp/sid_zkpp_instance.txt", "utf8").split(
      "\n",
    )) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) instanceCol[+m[1]] = leHex(m[2]);
    }
    const gLagrange = new Array<{ x: bigint; y: bigint }>(N);
    const gCoeff = new Array<{ x: bigint; y: bigint }>(N);
    let w!: { x: bigint; y: bigint };
    let u!: { x: bigint; y: bigint };
    for (const l of readFileSync("/tmp/sid_zkpp_srs.txt", "utf8").split("\n")) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m)
        gLagrange[+m[1]] = Vesta.fromBytes(fromHex(m[2])) as {
          x: bigint;
          y: bigint;
        };
      m = l.match(/^G:(\d+):(.+)$/);
      if (m)
        gCoeff[+m[1]] = Vesta.fromBytes(fromHex(m[2])) as {
          x: bigint;
          y: bigint;
        };
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHex(m[1])) as { x: bigint; y: bigint };
      m = l.match(/^U:(.+)$/);
      if (m) u = Vesta.fromBytes(fromHex(m[1])) as { x: bigint; y: bigint };
    }
    const vkRepr = leHex(
      readFileSync("/tmp/sid_zkpp_pk.txt", "utf8").match(
        /PK_VK_REPR=(\w+)/,
      )![1],
    );
    const cs = readFileSync("/tmp/sid_zkpp_cs.txt", "utf8").split("\n");
    const gates: Ast[] = [];
    const lkin: Ast[][] = [];
    const lktab: Ast[][] = [];
    const permMap: { col: number; ty: string }[] = [];
    const parseQ = (tag: string): Query[] => {
      const q: Query[] = [];
      for (const l of cs) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(-?\\d+):(-?\\d+)$`));
        if (m) q[+m[1]] = { col: +m[2], rot: +m[3] };
      }
      return q;
    };
    for (const l of cs) {
      let m = l.match(/^GATE:\d+:\d+:(.+)$/);
      if (m) gates.push(JSON.parse(m[1]) as Ast);
      m = l.match(/^LKIN:(\d+):(\d+):(.+)$/);
      if (m) (lkin[+m[1]] ??= [])[+m[2]] = JSON.parse(m[3]) as Ast;
      m = l.match(/^LKTAB:(\d+):(\d+):(.+)$/);
      if (m) (lktab[+m[1]] ??= [])[+m[2]] = JSON.parse(m[3]) as Ast;
      m = l.match(/^PERM:(\d+):(\d+):(\w+)/);
      if (m) permMap[+m[1]] = { col: +m[2], ty: m[3] };
    }
    const delta = leHex(
      readFileSync("/tmp/sid_perm_z.txt", "utf8").match(
        /DUMP_PERM_DELTA=(\w+)/,
      )?.[1] ??
        "a29b7bdd20cd6c6a3656ee3ef1f3e4f59d04a512715b45bd6cab06000f7d750a",
    );
    const params: ProverParams = {
      gLagrange,
      gCoeff,
      w,
      u,
      fixed,
      sigmas,
      vkRepr,
      gates,
      lkin,
      lktab,
      permMap,
      aq: parseQ("AQ"),
      fq: parseQ("FQ"),
      iq: parseQ("IQ"),
      l0: loadExt("L0"),
      lLast: loadExt("LLAST"),
      lBlind: loadExt("LBLIND"),
      xc: loadExt("XC"),
      omega: omegaForSize(K),
      delta,
    };

    const { advice, instance } = buildAdvice(
      [...new TextEncoder().encode("Str0ngP@ss")],
      3n,
      CE,
    );
    // the derived instance must match the dumped public inputs
    expect(instance[0]).toBe(instanceCol[0]);
    expect(instance[1]).toBe(instanceCol[1]);
    expect(instance[2]).toBe(instanceCol[2]);
    const toHex = (p: Uint8Array) =>
      [...p].map((b) => b.toString(16).padStart(2, "0")).join("");
    const ref = readFileSync("/tmp/sid_zkpp_proof.txt", "utf8").split("\n")[1];

    let lastFrac = 0;
    const t0 = Date.now();
    const proof = await createProof(advice, instance, params, {
      onProgress: (p) => {
        lastFrac = p.fraction;
      },
    });
    console.log(
      `END-TO-END byte-exact: ${toHex(proof) === ref} (len ${proof.length}); ${Date.now() - t0}ms; gauge ${lastFrac}`,
    );
    expect(proof.length).toBe(12352);
    expect(lastFrac).toBe(1);
    expect(toHex(proof)).toBe(ref);

    // workers path (Node: inline fallback) must be byte-identical.
    const { advice: a2, instance: i2 } = buildAdvice(
      [...new TextEncoder().encode("Str0ngP@ss")],
      3n,
      CE,
    );
    const proofW = await createProof(a2, i2, params, { workers: true });
    expect(toHex(proofW)).toBe(ref);
  }, 600000);
});
