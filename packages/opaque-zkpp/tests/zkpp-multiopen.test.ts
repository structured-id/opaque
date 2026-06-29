// Multiopen q_prime commitment: construct_intermediate_sets (group queries by
// point-set) + buildMultiopen + commit, byte-exact vs Rust proof[353]. Reads /tmp.
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { Fp } from "../src/field.js";
import { Vesta } from "../src/curve.js";
import { lagrangeToCoeff } from "../src/domain.js";
import { omegaForSize } from "../src/fft.js";
import { leHex } from "../src/gate-eval.js";
import {
  CounterRng,
  buildMultiopen,
  buildIPA,
  type MultiopenSet,
} from "../src/prover.js";

const N = 2048;
const K = 11;
const fromHex = (h: string) =>
  Uint8Array.from(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));

interface Query {
  id: string;
  poly: bigint[];
  point: bigint;
}

// halo2 construct_intermediate_sets: first-seen point indices, group commitments
// by their (sorted) point-index set; commitment order = first-seen in query list.
function constructIntermediateSets(queries: Query[]): {
  sets: MultiopenSet[];
  commitOrder: { id: string; setIdx: number }[];
} {
  const pointIdx = new Map<bigint, number>();
  const commits = new Map<string, { poly: bigint[]; pts: number[] }>();
  for (const q of queries) {
    if (!pointIdx.has(q.point)) pointIdx.set(q.point, pointIdx.size);
    const pi = pointIdx.get(q.point)!;
    if (!commits.has(q.id)) commits.set(q.id, { poly: q.poly, pts: [] });
    commits.get(q.id)!.pts.push(pi);
  }
  const invPoint = new Map<number, bigint>();
  for (const [pt, i] of pointIdx) invPoint.set(i, pt);
  const setIdx = new Map<string, number>();
  const commitSet = new Map<string, number[]>();
  for (const [id, d] of commits) {
    const s = [...new Set(d.pts)].sort((a, b) => a - b);
    commitSet.set(id, s);
    const key = s.join(",");
    if (!setIdx.has(key)) setIdx.set(key, setIdx.size);
  }
  const sets: MultiopenSet[] = Array.from({ length: setIdx.size }, () => ({
    polys: [],
    points: [],
  }));
  for (const [key, si] of setIdx)
    sets[si].points = key.split(",").map((n) => invPoint.get(+n)!);
  const commitOrder: { id: string; setIdx: number }[] = [];
  for (const [id, d] of commits) {
    const si = setIdx.get(commitSet.get(id)!.join(","))!;
    sets[si].polys.push(d.poly);
    commitOrder.push({ id, setIdx: si });
  }
  return { sets, commitOrder };
}

describe("multiopen q_prime commitment", () => {
  it("construct_intermediate_sets + buildMultiopen q_prime matches proof[353]", () => {
    if (!existsSync("/tmp/sid_mo.txt") || !existsSync("/tmp/sid_hpoly.txt")) {
      console.log("SKIP");
      return;
    }
    const x = leHex(
      "8176ef85595455da940b6aa36cdd5dc7807a724b58af8ef0148af74bdb7f8517",
    );
    const beta = leHex(
      "86e847078d289eabd9a203471b4964c924080266dda9710142fbaa8f0c0c2837",
    );
    const gammaReal = leHex(
      "cc5a8802603ccdca3f9dd351ec911c1f03d181e5ebcfc58635a9133dd4d8bf13",
    );
    const mo = (k: string) =>
      leHex(
        readFileSync("/tmp/sid_mo.txt", "utf8").match(
          new RegExp(`DUMP_${k}=(\\w+)`),
        )![1],
      );
    const x1 = mo("X1"),
      x2 = mo("X2"),
      x3 = mo("X3"),
      x4 = mo("X4");
    const omega = omegaForSize(K);
    const pw = (rot: number) =>
      Fp.mul(x, Fp.pow(omega, BigInt(((rot % N) + N) % N)));
    const xw = pw(1),
      xInv = pw(-1),
      xLast = pw(-6);
    // SRS g + w.
    const g: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint };
    for (const l of readFileSync("/tmp/sid_zkpp_srs.txt", "utf8").split("\n")) {
      let m = l.match(/^G:(\d+):(.+)$/);
      if (m) g[+m[1]] = Vesta.fromBytes(fromHex(m[2])) as any;
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHex(m[1])) as any;
    }
    const loadL = (path: string, tag: string, nc: number) => {
      const c = Array.from({ length: nc }, () => Array(N).fill(0n));
      for (const l of readFileSync(path, "utf8").split("\n")) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(\\d+):(.+)$`));
        if (m) c[+m[1]][+m[2]] = leHex(m[3]);
      }
      return c;
    };
    const adviceC = loadL("/tmp/sid_zkpp_advice.txt", "A", 53).map((c) =>
      lagrangeToCoeff(c, K),
    );
    const fixedC = loadL("/tmp/sid_zkpp_pk.txt", "F", 55).map((c) =>
      lagrangeToCoeff(c, K),
    );
    const sigmaC = loadL("/tmp/sid_zkpp_pk.txt", "S", 56).map((c) =>
      lagrangeToCoeff(c, K),
    );
    const inst = Array(N).fill(0n);
    for (const l of readFileSync("/tmp/sid_zkpp_instance.txt", "utf8").split(
      "\n",
    )) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) inst[+m[1]] = leHex(m[2]);
    }
    const instanceC = [lagrangeToCoeff(inst, K)];
    // perm Z coeff (blinded), lookup z/A'/S' coeff (blinded).
    const zdump = readFileSync("/tmp/sid_perm_z.txt", "utf8")
      .split("\n")
      .filter((s) => s.startsWith("DUMP_PERM_Z="))
      .map((s) => s.slice(12));
    let rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14; i++) rng.nextScalar();
    const permZC: bigint[][] = [];
    for (let c = 0; c < 8; c++) {
      const z = Array.from({ length: N }, (_, i) =>
        leHex(zdump[c].slice(i * 64, i * 64 + 64)),
      );
      for (let r = N - 5; r < N; r++) z[r] = rng.nextScalar();
      rng.nextScalar();
      permZC.push(lagrangeToCoeff(z, K));
    }
    const parseCol = (h: string) =>
      Array.from({ length: N }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const lk = readFileSync("/tmp/sid_lk.txt", "utf8").split("\n"),
      lk2 = readFileSync("/tmp/sid_lk2.txt", "utf8").split("\n");
    const cins = lk
      .filter((s) => s.startsWith("DUMP_LK_CIN="))
      .map((s) => parseCol(s.slice(12)));
    const ctabs = lk
      .filter((s) => s.startsWith("DUMP_LK_CTAB="))
      .map((s) => parseCol(s.slice(13)));
    const aps = lk2
      .filter((s) => s.startsWith("DUMP_LK_AP="))
      .map((s) => parseCol(s.slice(11)));
    const sps = lk2
      .filter((s) => s.startsWith("DUMP_LK_SP="))
      .map((s) => parseCol(s.slice(11)));
    rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14 + 8 * 6; i++) rng.nextScalar();
    const lzC: bigint[][] = [],
      aC: bigint[][] = [],
      sC: bigint[][] = [];
    for (let l = 0; l < 6; l++) {
      const lp = Array.from({ length: N }, (_, i) =>
        Fp.mul(
          Fp.mul(Fp.add(cins[l][i], beta), Fp.add(ctabs[l][i], gammaReal)),
          Fp.inv(Fp.mul(Fp.add(aps[l][i], beta), Fp.add(sps[l][i], gammaReal))),
        ),
      );
      const z = new Array(N).fill(0n);
      z[0] = 1n;
      for (let i = 1; i < N - 5; i++) z[i] = Fp.mul(z[i - 1], lp[i - 1]);
      for (let i = N - 5; i < N; i++) z[i] = rng.nextScalar();
      rng.nextScalar();
      lzC.push(lagrangeToCoeff(z, K));
      aC.push(lagrangeToCoeff(aps[l], K));
      sC.push(lagrangeToCoeff(sps[l], K));
    }
    // h_combined = sum_k h_pieces[k]·(x^n)^k (vanishing.evaluate reversed fold).
    const hpoly = readFileSync("/tmp/sid_hpoly.txt", "utf8")
      .split("\n")
      .find((s) => s.startsWith("DUMP_HPOLY="))!
      .slice("DUMP_HPOLY=".length);
    const xn = Fp.pow(x, BigInt(N));
    const hCombined = Array(N).fill(0n);
    let xnk = 1n;
    for (let k = 0; k < 8; k++) {
      for (let i = 0; i < N; i++)
        hCombined[i] = Fp.add(
          hCombined[i],
          Fp.mul(
            leHex(hpoly.slice((k * N + i) * 64, (k * N + i) * 64 + 64)),
            xnk,
          ),
        );
      xnk = Fp.mul(xnk, xn);
    }
    // vanishing random poly (rng offset 539).
    rng = new CounterRng();
    for (let i = 0; i < 53 * 6 + 53 + 6 * 14 + 8 * 6 + 6 * 6; i++)
      rng.nextScalar();
    const randomPoly = Array.from({ length: N }, () => rng.nextScalar());
    // queries (regexp index order TAG:i:col:rot).
    const parseQ = (tag: string) => {
      const q: { col: number; rot: number }[] = [];
      for (const l of readFileSync("/tmp/sid_zkpp_cs.txt", "utf8").split(
        "\n",
      )) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(-?\\d+):(-?\\d+)$`));
        if (m) q[+m[1]] = { col: +m[2], rot: +m[3] };
      }
      return q;
    };
    const queries: Query[] = [];
    for (const q of parseQ("IQ"))
      queries.push({
        id: `i${q.col}`,
        poly: instanceC[q.col],
        point: pw(q.rot),
      });
    for (const q of parseQ("AQ"))
      queries.push({ id: `a${q.col}`, poly: adviceC[q.col], point: pw(q.rot) });
    // permutation sets: all sets (x, x_next), then sets 6..0 (x_last).
    for (let c = 0; c < 8; c++) {
      queries.push({ id: `pz${c}`, poly: permZC[c], point: x });
      queries.push({ id: `pz${c}`, poly: permZC[c], point: xw });
    }
    for (let c = 6; c >= 0; c--)
      queries.push({ id: `pz${c}`, poly: permZC[c], point: xLast });
    // lookups: product@x, pi@x, pt@x, pi@x_inv, product@x_next.
    for (let l = 0; l < 6; l++) {
      queries.push({ id: `lz${l}`, poly: lzC[l], point: x });
      queries.push({ id: `lai${l}`, poly: aC[l], point: x });
      queries.push({ id: `lat${l}`, poly: sC[l], point: x });
      queries.push({ id: `lai${l}`, poly: aC[l], point: xInv });
      queries.push({ id: `lz${l}`, poly: lzC[l], point: xw });
    }
    for (const q of parseQ("FQ"))
      queries.push({ id: `f${q.col}`, poly: fixedC[q.col], point: pw(q.rot) });
    for (let j = 0; j < 56; j++)
      queries.push({ id: `s${j}`, poly: sigmaC[j], point: x });
    queries.push({ id: "h", poly: hCombined, point: x });
    queries.push({ id: "rand", poly: randomPoly, point: x });
    const { sets, commitOrder } = constructIntermediateSets(queries);
    const { qPrime, qEvals, pPoly } = buildMultiopen(sets, x1, x2, x3, x4, N);
    const hx = (b: Uint8Array) =>
      [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
    const feS = (v: bigint) =>
      [...Fp.toBytes(v)].map((b) => b.toString(16).padStart(2, "0")).join("");
    const proofHex = readFileSync("/tmp/sid_zkpp_proof.txt", "utf8").split(
      "\n",
    )[1];
    const at = (i: number) => proofHex.slice(i * 64, i * 64 + 64);
    // blinds per commitment (CounterRng positions in the create_proof order).
    const rngAt = (k: number) => {
      const r = new CounterRng();
      for (let i = 0; i < k; i++) r.nextScalar();
      return r.nextScalar();
    };
    let hBlind = 0n,
      hxnk = 1n;
    for (let k = 0; k < 8; k++) {
      hBlind = Fp.add(hBlind, Fp.mul(rngAt(2588 + k), hxnk));
      hxnk = Fp.mul(hxnk, xn);
    }
    const blindOf = (id: string): bigint => {
      if (id.startsWith("pz")) return rngAt(460 + +id.slice(2) * 6);
      if (id.startsWith("lz")) return rngAt(508 + +id.slice(2) * 6);
      if (id.startsWith("lai")) return rngAt(383 + +id.slice(3) * 14);
      if (id.startsWith("lat")) return rngAt(384 + +id.slice(3) * 14);
      if (id.startsWith("a")) return rngAt(318 + +id.slice(1));
      if (id === "h") return hBlind;
      if (id === "rand") return rngAt(2587);
      return 1n; // Blind::default() = ONE (instance, fixed, sigma)
    };
    const qpBlind = rngAt(2596);
    // q_blinds (accumulate via x1 in commitment order) + p_blind (fold via x4).
    const qBlinds = Array(sets.length).fill(0n);
    for (const { id, setIdx } of commitOrder)
      qBlinds[setIdx] = Fp.add(Fp.mul(qBlinds[setIdx], x1), blindOf(id));
    let pBlind = qpBlind;
    for (const qb of qBlinds) pBlind = Fp.add(Fp.mul(pBlind, x4), qb);
    // --- verify multiopen + IPA tail vs proof[353..385] ---
    const qpCommit = hx(
      Vesta.toBytes(
        Vesta.add(Vesta.msm(qPrime, g), Vesta.scalarMul(qpBlind, w)),
      ),
    );
    const qpOk = qpCommit === at(353);
    let qeOk = 0;
    for (let i = 0; i < qEvals.length; i++)
      if (feS(qEvals[i]) === at(354 + i)) qeOk++;
    // IPA.
    let u!: { x: bigint; y: bigint };
    for (const l of readFileSync("/tmp/sid_zkpp_srs.txt", "utf8").split("\n")) {
      const m = l.match(/^U:(.+)$/);
      if (m) u = Vesta.fromBytes(fromHex(m[1])) as any;
    }
    const xi = mo("IPA_XI"),
      z = mo("IPA_Z");
    const uCh: bigint[] = [];
    for (let j = 0; j < K; j++) uCh.push(mo(`IPA_U${j}`));
    const ipaRng = new CounterRng();
    for (let i = 0; i < 2597; i++) ipaRng.nextScalar();
    const { sCommit, lr, c, f } = buildIPA(
      pPoly,
      pBlind,
      x3,
      g,
      w,
      u,
      xi,
      z,
      uCh,
      ipaRng,
      K,
    );
    const sOk = hx(Vesta.toBytes(sCommit as any)) === at(361);
    let lrOk = 0;
    for (let j = 0; j < K; j++) {
      if (hx(Vesta.toBytes(lr[j][0] as any)) === at(362 + 2 * j)) lrOk++;
      if (hx(Vesta.toBytes(lr[j][1] as any)) === at(363 + 2 * j)) lrOk++;
    }
    const cOk = feS(c) === at(384),
      fOk = feS(f) === at(385);
    console.log(
      `MULTIOPEN+IPA: qprime=${qpOk} qevals=${qeOk}/${qEvals.length} sCommit=${sOk} lr=${lrOk}/${2 * K} c=${cOk} f=${fOk}`,
    );
    expect(
      qpOk && qeOk === qEvals.length && sOk && lrOk === 2 * K && cOk && fOk,
    ).toBe(true);
  }, 120000);
});
