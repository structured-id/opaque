// End-to-end create_proof assembly: runs every verified stage through one
// transcript + CounterRng, concatenates the 386 proof items, and checks the
// result is byte-identical to the Rust proof (12352 bytes). Also times it (bench).
// Witness = dumped advice. Reads /tmp — skips in CI.
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { Fp } from "../src/field.js";
import { Vesta } from "../src/curve.js";
import { Transcript } from "../src/transcript.js";
import {
  lagrangeToCoeff,
  coeffToExtended,
  extendedToCoeff,
  vanishingTInv,
  divideByVanishing,
} from "../src/domain.js";
import { omegaForSize } from "../src/fft.js";
import {
  evalAst,
  compileAst,
  leHex,
  type Ast,
  type EvalCtx,
} from "../src/gate-eval.js";
import {
  CounterRng,
  evalPolynomial,
  permutationZChunk,
  kateDivision,
  permuteExpressionPair,
  type MultiopenSet,
} from "../src/prover.js";

const N = 2048,
  K = 11,
  EXTK = 14,
  EXTN = 1 << EXTK,
  QPD = EXTN / N,
  BF = 5;
const fromHex = (h: string) =>
  Uint8Array.from(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
const hx = (b: Uint8Array) =>
  [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
const ptHex = (p: { x: bigint; y: bigint }) => hx(Vesta.toBytes(p as any));
const scHex = (v: bigint) =>
  [...Fp.toBytes(v)].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("end-to-end create_proof assembly", () => {
  it("produces byte-identical proof (12352 bytes) and benches", () => {
    if (
      !existsSync("/tmp/sid_zkpp_proof.txt") ||
      !existsSync("/tmp/sid_mo.txt")
    ) {
      console.log("SKIP");
      return;
    }
    // ---- load keys + witness ----
    const loadL = (path: string, tag: string, nc: number) => {
      const c = Array.from({ length: nc }, () => Array(N).fill(0n));
      for (const l of readFileSync(path, "utf8").split("\n")) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(\\d+):(.+)$`));
        if (m) c[+m[1]][+m[2]] = leHex(m[3]);
      }
      return c;
    };
    const loadExt = (tag: string) => {
      const a = Array(EXTN).fill(0n);
      for (const l of readFileSync("/tmp/sid_zkpp_pk.txt", "utf8").split(
        "\n",
      )) {
        const m = l.match(new RegExp(`^${tag}:(\\d+):(.+)$`));
        if (m) a[+m[1]] = leHex(m[2]);
      }
      return a;
    };
    const advice = loadL("/tmp/sid_zkpp_advice.txt", "A", 53);
    const fixed = loadL("/tmp/sid_zkpp_pk.txt", "F", 55);
    const sigmas = loadL("/tmp/sid_zkpp_pk.txt", "S", 56);
    const instArr = Array(N).fill(0n);
    for (const l of readFileSync("/tmp/sid_zkpp_instance.txt", "utf8").split(
      "\n",
    )) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) instArr[+m[1]] = leHex(m[2]);
    }
    const instance = [instArr];
    const l0 = loadExt("L0"),
      lLast = loadExt("LLAST"),
      lBlind = loadExt("LBLIND"),
      XC = loadExt("XC");
    const gL: { x: bigint; y: bigint }[] = new Array(N),
      gC: { x: bigint; y: bigint }[] = new Array(N);
    let w!: { x: bigint; y: bigint }, u!: { x: bigint; y: bigint };
    for (const l of readFileSync("/tmp/sid_zkpp_srs.txt", "utf8").split("\n")) {
      let m = l.match(/^GL:(\d+):(.+)$/);
      if (m) gL[+m[1]] = Vesta.fromBytes(fromHex(m[2])) as any;
      m = l.match(/^G:(\d+):(.+)$/);
      if (m) gC[+m[1]] = Vesta.fromBytes(fromHex(m[2])) as any;
      m = l.match(/^W:(.+)$/);
      if (m) w = Vesta.fromBytes(fromHex(m[1])) as any;
      m = l.match(/^U:(.+)$/);
      if (m) u = Vesta.fromBytes(fromHex(m[1])) as any;
    }
    const vkRepr = leHex(
      readFileSync("/tmp/sid_zkpp_pk.txt", "utf8").match(
        /PK_VK_REPR=(\w+)/,
      )![1],
    );
    const cs = readFileSync("/tmp/sid_zkpp_cs.txt", "utf8").split("\n");
    const gates: Ast[] = [];
    const lkin: Ast[][] = [],
      lktab: Ast[][] = [];
    const permMap: { col: number; ty: string }[] = [];
    const parseQ = (tag: string) => {
      const q: { col: number; rot: number }[] = [];
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
    const omega = omegaForSize(K),
      delta = leHex(
        readFileSync("/tmp/sid_perm_z.txt", "utf8").match(
          /DUMP_PERM_DELTA=(\w+)/,
        )?.[1] ??
          "a29b7bdd20cd6c6a3656ee3ef1f3e4f59d04a512715b45bd6cab06000f7d750a",
      );

    const proofRef = readFileSync("/tmp/sid_zkpp_proof.txt", "utf8").split(
      "\n",
    )[1];
    const t0 = Date.now();
    const T = (l: string) => console.log(`  [+${Date.now() - t0}ms] ${l}`);
    // ---- run prover ----
    const rng = new CounterRng();
    const t = new Transcript();
    let proof = "";
    const ctx: EvalCtx = { advice, fixed, instance, n: N };
    t.commonScalar(vkRepr);
    // instance commit (Blind::default = ONE), absorbed not written.
    t.commonPoint(
      Vesta.add(Vesta.msm(instArr, gL), Vesta.scalarMul(1n, w)) as any,
    );
    // stage 1: advice commits (53). RNG: 53*6 blinding rows (col-major) then 53 blinds.
    const adviceBlinds: bigint[] = [];
    for (let c = 0; c < 53; c++)
      for (let r = N - 6; r < N; r++) advice[c][r] = rng.nextScalar();
    for (let c = 0; c < 53; c++) adviceBlinds.push(rng.nextScalar());
    const adviceCommits = advice.map((col, c) =>
      Vesta.add(Vesta.msm(col, gL), Vesta.scalarMul(adviceBlinds[c], w)),
    );
    for (const p of adviceCommits) {
      const h = ptHex(p);
      proof += h;
      t.commonPoint(p as any);
    }
    const theta = t.squeezeChallenge();
    // stage 3: lookup compress + permute + commit (12).
    const compress = (exprs: Ast[]) =>
      Array.from({ length: N }, (_, r) => {
        let a = 0n;
        for (const e of exprs) a = Fp.add(Fp.mul(a, theta), evalAst(e, r, ctx));
        return a;
      });
    const cins: bigint[][] = [],
      ctabs: bigint[][] = [],
      aps: bigint[][] = [],
      sps: bigint[][] = [];
    const apCommits: { x: bigint; y: bigint }[] = [],
      spCommits: { x: bigint; y: bigint }[] = [];
    for (let lp = 0; lp < 6; lp++) {
      const cin = compress(lkin[lp]),
        ctab = compress(lktab[lp]);
      const { pInput: ap, pTable: sp } = permuteExpressionPair(
        cin,
        ctab,
        N - (BF + 1),
        BF,
        rng,
      );
      const apBlind = rng.nextScalar(),
        spBlind = rng.nextScalar();
      cins.push(cin);
      ctabs.push(ctab);
      aps.push(ap);
      sps.push(sp);
      apCommits.push(Vesta.add(Vesta.msm(ap, gL), Vesta.scalarMul(apBlind, w)));
      spCommits.push(Vesta.add(Vesta.msm(sp, gL), Vesta.scalarMul(spBlind, w)));
    }
    for (let lp = 0; lp < 6; lp++) {
      for (const p of [apCommits[lp], spCommits[lp]]) {
        proof += ptHex(p);
        t.commonPoint(p as any);
      }
    }
    const beta = t.squeezeChallenge(),
      gamma = t.squeezeChallenge();
    // stage 5: permutation Z (8 chunks) + commits.
    const permCol = permMap.map((m) =>
      m.ty === "Advice"
        ? advice[m.col]
        : m.ty === "Fixed"
          ? fixed[m.col]
          : instance[m.col],
    );
    const dpow = [1n];
    for (let i = 1; i < 56; i++) dpow.push(Fp.mul(dpow[i - 1], delta));
    let lastZ = 1n;
    const permZ: bigint[][] = [];
    for (let c = 0; c < 8; c++) {
      const cols = permCol.slice(c * 7, c * 7 + 7),
        sig = sigmas.slice(c * 7, c * 7 + 7),
        dps = dpow.slice(c * 7, c * 7 + 7);
      const z = permutationZChunk(cols, sig, dps, beta, gamma, K, lastZ);
      lastZ = z[N - 6];
      permZ.push(z);
    }
    for (let c = 0; c < 8; c++) {
      for (let r = N - 5; r < N; r++) permZ[c][r] = rng.nextScalar();
      const bl = rng.nextScalar();
      const p = Vesta.add(Vesta.msm(permZ[c], gL), Vesta.scalarMul(bl, w));
      proof += ptHex(p);
      t.commonPoint(p as any);
    }
    // lookup Z (6) + commits.
    const lookZ: bigint[][] = [];
    for (let lp = 0; lp < 6; lp++) {
      const lpr = Array.from({ length: N }, (_, i) =>
        Fp.mul(
          Fp.mul(Fp.add(cins[lp][i], beta), Fp.add(ctabs[lp][i], gamma)),
          Fp.inv(Fp.mul(Fp.add(aps[lp][i], beta), Fp.add(sps[lp][i], gamma))),
        ),
      );
      const z = new Array(N).fill(0n);
      z[0] = 1n;
      for (let i = 1; i < N - 5; i++) z[i] = Fp.mul(z[i - 1], lpr[i - 1]);
      for (let i = N - 5; i < N; i++) z[i] = rng.nextScalar();
      const bl = rng.nextScalar();
      lookZ.push(z);
      const p = Vesta.add(Vesta.msm(z, gL), Vesta.scalarMul(bl, w));
      proof += ptHex(p);
      t.commonPoint(p as any);
    }
    // vanishing random poly + commit.
    const randomPoly = Array.from({ length: N }, () => rng.nextScalar());
    const randomBlind = rng.nextScalar();
    {
      const p = Vesta.add(
        Vesta.msm(randomPoly, gC),
        Vesta.scalarMul(randomBlind, w),
      );
      proof += ptHex(p);
      t.commonPoint(p as any);
    }
    const y = t.squeezeChallenge();
    T("commits done (advice/lookups/permZ/lookupZ/vanishing) -> y");
    // stage 6: quotient h.
    const toCos = (col: bigint[]) =>
      coeffToExtended(lagrangeToCoeff(col, K), EXTK);
    const adviceCos = advice.map(toCos),
      fixedCos = fixed.map(toCos),
      instCos = instance.map(toCos);
    const cosCtx: EvalCtx = {
      advice: adviceCos,
      fixed: fixedCos,
      instance: instCos,
      n: EXTN,
      rotScale: QPD,
    };
    const sigCos = sigmas.map(toCos),
      // perm columns are a subset of advice/fixed/instance — reuse their cosets
      // instead of recomputing 56 FFTs.
      permColCos = permMap.map((m) =>
        m.ty === "Advice"
          ? adviceCos[m.col]
          : m.ty === "Fixed"
            ? fixedCos[m.col]
            : instCos[m.col],
      ),
      permZCos = permZ.map(toCos);
    const apCos = aps.map(toCos),
      spCos = sps.map(toCos),
      lookZCos = lookZ.map(toCos);
    const compressCos = (exprs: Ast[]) => {
      const fns = exprs.map((ex) => compileAst(ex, QPD, EXTN));
      return Array.from({ length: EXTN }, (_, j) => {
        let a = 0n;
        for (const f of fns) a = Fp.add(Fp.mul(a, theta), f(j, cosCtx));
        return a;
      });
    };
    const cinCos = lkin.map(compressCos);
    const ctabCos = lktab.map(compressCos);
    const rot = (a: bigint[], j: number, sh: number) =>
      a[(((j + sh) % EXTN) + EXTN) % EXTN];
    T("cosets computed (~250 FFTs of size 16384)");
    const gateFns = gates.map((g) => compileAst(g, QPD, EXTN));
    const folded = new Array(EXTN);
    for (let j = 0; j < EXTN; j++) {
      let acc = 0n;
      for (const gf of gateFns) acc = Fp.add(Fp.mul(acc, y), gf(j, cosCtx));
      // permutation terms (17)
      const pe: bigint[] = [];
      pe.push(Fp.mul(l0[j], Fp.sub(1n, permZCos[0][j])));
      pe.push(
        Fp.mul(
          lLast[j],
          Fp.sub(Fp.mul(permZCos[7][j], permZCos[7][j]), permZCos[7][j]),
        ),
      );
      for (let c = 1; c < 8; c++)
        pe.push(
          Fp.mul(
            l0[j],
            Fp.sub(permZCos[c][j], rot(permZCos[c - 1], j, -6 * QPD)),
          ),
        );
      const act = Fp.sub(1n, Fp.add(lLast[j], lBlind[j]));
      for (let c = 0; c < 8; c++) {
        let left = rot(permZCos[c], j, QPD),
          right = permZCos[c][j];
        for (let k = 0; k < 7; k++) {
          const g = c * 7 + k;
          left = Fp.mul(
            left,
            Fp.add(Fp.add(permColCos[g][j], Fp.mul(beta, sigCos[g][j])), gamma),
          );
          right = Fp.mul(
            right,
            Fp.add(
              Fp.add(permColCos[g][j], Fp.mul(Fp.mul(beta, dpow[g]), XC[j])),
              gamma,
            ),
          );
        }
        pe.push(Fp.mul(act, Fp.sub(left, right)));
      }
      for (const e of pe) acc = Fp.add(Fp.mul(acc, y), e);
      // lookup terms (30)
      for (let lp = 0; lp < 6; lp++) {
        const z = lookZCos[lp],
          A = apCos[lp],
          S = spCos[lp],
          cin = cinCos[lp],
          ctab = ctabCos[lp];
        const le = [
          Fp.mul(l0[j], Fp.sub(1n, z[j])),
          Fp.mul(lLast[j], Fp.sub(Fp.mul(z[j], z[j]), z[j])),
          Fp.mul(
            act,
            Fp.sub(
              Fp.mul(
                Fp.mul(rot(z, j, QPD), Fp.add(A[j], beta)),
                Fp.add(S[j], gamma),
              ),
              Fp.mul(
                Fp.mul(z[j], Fp.add(cin[j], beta)),
                Fp.add(ctab[j], gamma),
              ),
            ),
          ),
          Fp.mul(l0[j], Fp.sub(A[j], S[j])),
          Fp.mul(
            Fp.mul(act, Fp.sub(A[j], S[j])),
            Fp.sub(A[j], rot(A, j, -QPD)),
          ),
        ];
        for (const e of le) acc = Fp.add(Fp.mul(acc, y), e);
      }
      folded[j] = acc;
    }
    T("quotient folded loop (181 polys x 16384 AST evals)");
    const hCoeff = extendedToCoeff(
      divideByVanishing(folded, vanishingTInv(K, EXTK)),
      K,
      EXTK,
      QPD,
    );
    for (let p = 0; p < 8; p++) {
      const piece = hCoeff.slice(p * N, (p + 1) * N);
      const bl = rng.nextScalar();
      const pt = Vesta.add(Vesta.msm(piece, gC), Vesta.scalarMul(bl, w));
      proof += ptHex(pt);
      t.commonPoint(pt as any);
    }
    const x = t.squeezeChallenge();
    T("h split + 8 commits -> x");
    // stage 7: evaluations.
    const xrot = (r: number) =>
      Fp.mul(x, Fp.pow(omega, BigInt(((r % N) + N) % N)));
    const adviceCoeff = advice.map((c) => lagrangeToCoeff(c, K)),
      fixedCoeff = fixed.map((c) => lagrangeToCoeff(c, K)),
      instCoeff = instance.map((c) => lagrangeToCoeff(c, K));
    const sigCoeff = sigmas.map((c) => lagrangeToCoeff(c, K));
    const permZCoeff = permZ.map((z) => lagrangeToCoeff(z, K)),
      lookZCoeff = lookZ.map((z) => lagrangeToCoeff(z, K));
    const apCoeff = aps.map((a) => lagrangeToCoeff(a, K)),
      spCoeff = sps.map((s) => lagrangeToCoeff(s, K));
    const writeEval = (v: bigint) => {
      proof += scHex(v);
      t.commonScalar(v);
    };
    for (const q of parseQ("IQ"))
      writeEval(evalPolynomial(instCoeff[q.col], xrot(q.rot)));
    for (const q of parseQ("AQ"))
      writeEval(evalPolynomial(adviceCoeff[q.col], xrot(q.rot)));
    for (const q of parseQ("FQ"))
      writeEval(evalPolynomial(fixedCoeff[q.col], xrot(q.rot)));
    writeEval(evalPolynomial(randomPoly, x));
    for (let j = 0; j < 56; j++) writeEval(evalPolynomial(sigCoeff[j], x));
    const xw = xrot(1),
      xLastP = xrot(-6),
      xInv = xrot(-1);
    for (let c = 0; c < 8; c++) {
      writeEval(evalPolynomial(permZCoeff[c], x));
      writeEval(evalPolynomial(permZCoeff[c], xw));
      if (c < 7) writeEval(evalPolynomial(permZCoeff[c], xLastP));
    }
    for (let lp = 0; lp < 6; lp++) {
      writeEval(evalPolynomial(lookZCoeff[lp], x));
      writeEval(evalPolynomial(lookZCoeff[lp], xw));
      writeEval(evalPolynomial(apCoeff[lp], x));
      writeEval(evalPolynomial(apCoeff[lp], xInv));
      writeEval(evalPolynomial(spCoeff[lp], x));
    }
    T("evaluations (265 evals + coeff FFTs)");
    // stage 8: multiopen.
    const x1 = t.squeezeChallenge(),
      x2 = t.squeezeChallenge();
    const xn = Fp.pow(x, BigInt(N));
    const hCombined = Array(N).fill(0n);
    let xnk = 1n;
    for (let k = 0; k < 8; k++) {
      for (let i = 0; i < N; i++)
        hCombined[i] = Fp.add(hCombined[i], Fp.mul(hCoeff[k * N + i], xnk));
      xnk = Fp.mul(xnk, xn);
    }
    interface Q {
      id: string;
      poly: bigint[];
      point: bigint;
    }
    const queries: Q[] = [];
    for (const q of parseQ("IQ"))
      queries.push({
        id: `i${q.col}`,
        poly: instCoeff[q.col],
        point: xrot(q.rot),
      });
    for (const q of parseQ("AQ"))
      queries.push({
        id: `a${q.col}`,
        poly: adviceCoeff[q.col],
        point: xrot(q.rot),
      });
    for (let c = 0; c < 8; c++) {
      queries.push({ id: `pz${c}`, poly: permZCoeff[c], point: x });
      queries.push({ id: `pz${c}`, poly: permZCoeff[c], point: xw });
    }
    for (let c = 6; c >= 0; c--)
      queries.push({ id: `pz${c}`, poly: permZCoeff[c], point: xLastP });
    for (let lp = 0; lp < 6; lp++) {
      queries.push({ id: `lz${lp}`, poly: lookZCoeff[lp], point: x });
      queries.push({ id: `lai${lp}`, poly: apCoeff[lp], point: x });
      queries.push({ id: `lat${lp}`, poly: spCoeff[lp], point: x });
      queries.push({ id: `lai${lp}`, poly: apCoeff[lp], point: xInv });
      queries.push({ id: `lz${lp}`, poly: lookZCoeff[lp], point: xw });
    }
    for (const q of parseQ("FQ"))
      queries.push({
        id: `f${q.col}`,
        poly: fixedCoeff[q.col],
        point: xrot(q.rot),
      });
    for (let j = 0; j < 56; j++)
      queries.push({ id: `s${j}`, poly: sigCoeff[j], point: x });
    queries.push({ id: "h", poly: hCombined, point: x });
    queries.push({ id: "rand", poly: randomPoly, point: x });
    // construct_intermediate_sets
    const pointIdx = new Map<bigint, number>(),
      commits = new Map<string, { poly: bigint[]; pts: number[] }>();
    for (const q of queries) {
      if (!pointIdx.has(q.point)) pointIdx.set(q.point, pointIdx.size);
      const pi = pointIdx.get(q.point)!;
      if (!commits.has(q.id)) commits.set(q.id, { poly: q.poly, pts: [] });
      commits.get(q.id)!.pts.push(pi);
    }
    const invPt = new Map<number, bigint>();
    for (const [pt, i] of pointIdx) invPt.set(i, pt);
    const setIdx = new Map<string, number>(),
      commitSet = new Map<string, number[]>();
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
      sets[si].points = key.split(",").map((n) => invPt.get(+n)!);
    const commitOrder: { id: string; setIdx: number }[] = [];
    for (const [id, d] of commits) {
      const si = setIdx.get(commitSet.get(id)!.join(","))!;
      sets[si].polys.push(d.poly);
      commitOrder.push({ id, setIdx: si });
    }
    // q_polys (x1 fold) + q_prime (kate by point-set, x2 fold).
    const qPolys = sets.map((s) =>
      s.polys.reduce<bigint[] | null>(
        (q, p) =>
          q === null ? p.slice() : q.map((v, i) => Fp.add(Fp.mul(v, x1), p[i])),
        null,
      )!,
    );
    let qPrime: bigint[] | null = null;
    sets.forEach((s, si) => {
      let poly = qPolys[si].slice();
      for (const pt of s.points) poly = kateDivision(poly, pt);
      while (poly.length < N) poly.push(0n);
      qPrime =
        qPrime === null
          ? poly
          : qPrime.map((v, i) => Fp.add(Fp.mul(v, x2), poly[i]));
    });
    // q_prime commit (coeff basis g) then x3.
    const qpBlind = rng.nextScalar();
    {
      const p = Vesta.add(Vesta.msm(qPrime!, gC), Vesta.scalarMul(qpBlind, w));
      proof += ptHex(p);
      t.commonPoint(p as any);
    }
    const x3 = t.squeezeChallenge();
    for (const q of qPolys) writeEval(evalPolynomial(q, x3));
    const x4 = t.squeezeChallenge();
    let pPoly = qPrime!.slice();
    for (const q of qPolys)
      pPoly = pPoly.map((v, i) => Fp.add(Fp.mul(v, x4), q[i]));
    // blinds for p_blind.
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
      return 1n;
    };
    const qBlinds = Array(sets.length).fill(0n);
    for (const { id, setIdx: si } of commitOrder)
      qBlinds[si] = Fp.add(Fp.mul(qBlinds[si], x1), blindOf(id));
    let pBlind = qpBlind;
    for (const qb of qBlinds) pBlind = Fp.add(Fp.mul(pBlind, x4), qb);
    // IPA (runIPA writes s_commit + squeezes xi/z, then 11 rounds of L/R).
    T("multiopen q_prime/q_evals -> x4");
    const { sCommit, lr, c, f } = runIPA(t, pPoly, pBlind, x3, gC, w, u, rng);
    T("IPA (s_poly + 11 rounds)");
    proof += ptHex(sCommit);
    for (const [L, R] of lr) {
      proof += ptHex(L);
      proof += ptHex(R);
    }
    proof += scHex(c);
    proof += scHex(f);
    const ms = Date.now() - t0;
    // ---- verify ----
    const ok = proof === proofRef;
    console.log(
      `FULL-PROOF byte-exact: ${ok} (len ${proof.length / 2} vs ${proofRef.length / 2}); prover ${ms}ms`,
    );
    if (!ok) {
      for (let i = 0; i < 386; i++)
        if (
          proof.slice(i * 64, i * 64 + 64) !==
          proofRef.slice(i * 64, i * 64 + 64)
        ) {
          console.log(`first mismatch at item ${i}`);
          break;
        }
    }
    // ---- per-gadget cost attribution (analysis only; ZKPP_GADGET_COST=1) ----
    // Gates/regions are not gadget-tagged in the dump, so attribute by advice
    // column ranges (from the circuit orchestration). Most proof cost (commits,
    // cosets, IPA) is per-column/global at fixed k=11, so this maps column
    // ownership -> gadget; the quotient (gate-eval) is timed per gate-group.
    if (process.env.ZKPP_GADGET_COST) {
      const gadgetOf = (c: number): string =>
        c <= 10
          ? "a"
          : c >= 11 && c <= 16
            ? "b"
            : c >= 18 && c <= 21
              ? "c-poseidon"
              : c >= 22 && c <= 27
                ? "c-binding"
                : c >= 34 && c <= 37
                  ? "c-hash2curve"
                  : c >= 39 && c <= 40
                    ? "d-breach"
                    : "misc";
      const adviceCols = (n: Ast): Set<number> => {
        const s = new Set<number>();
        const w = (x: Ast): void => {
          if (x[0] === "a") s.add(x[1]);
          else if (x[0] === "n" || x[0] === "s") w(x[1]);
          else if (x[0] === "+" || x[0] === "*") {
            w(x[1]);
            w(x[2]);
          }
        };
        w(n);
        return s;
      };
      // column ownership -> commits + cosets scale with this
      const colG: Record<string, number[]> = {};
      for (let c = 0; c < 53; c++) (colG[gadgetOf(c)] ??= []).push(c);
      console.log("\n=== per-gadget cost attribution ===");
      console.log(
        "-- advice columns per gadget (drives commits MSM + coset FFT) --",
      );
      for (const [g, cols] of Object.entries(colG))
        console.log(
          `  ${g.padEnd(13)} ${cols.length} cols  [${cols.join(",")}]`,
        );
      // gate grouping by gadget(s) of referenced advice cols
      const gg: Record<string, number[]> = {};
      gates.forEach((g, i) => {
        const gs = [...new Set([...adviceCols(g)].map(gadgetOf))].sort();
        (gg[gs.length ? gs.join("+") : "const"] ??= []).push(i);
      });
      console.log("-- quotient gate-eval per gate-group (timed over coset) --");
      for (const [k, idxs] of Object.entries(gg)) {
        const fns = idxs.map((i) => gateFns[i]);
        const tg = Date.now();
        let sink = 0n;
        for (let j = 0; j < EXTN; j++)
          for (const f of fns) sink = Fp.add(sink, f(j, cosCtx));
        if (sink === 123456789n) console.log("");
        console.log(
          `  ${k.padEnd(22)} ${String(idxs.length).padStart(3)} polys  ${Date.now() - tg}ms`,
        );
      }
      console.log(`-- lookups: ${lkin.length} (breach/gadget_d) --`);
      console.log(
        `   commits: 6 perm-input + 6 perm-table + 6 Z = 18 MSM of 89; plus 6 cosets each ap/sp/lookZ/cin/ctab; plus grand-product inversions`,
      );
    }
    expect(ok).toBe(true);
  }, 600000);
});

// IPA with proper transcript threading (s_commit written + absorbed, then xi/z, rounds).
function runIPA(
  t: Transcript,
  pPoly: bigint[],
  pBlind: bigint,
  x3: bigint,
  g: { x: bigint; y: bigint }[],
  w: { x: bigint; y: bigint },
  u: { x: bigint; y: bigint },
  rng: CounterRng,
) {
  const n = pPoly.length,
    k = Math.log2(n);
  const sPoly = Array.from({ length: n }, () => rng.nextScalar());
  sPoly[0] = Fp.sub(sPoly[0], evalPolynomial(sPoly, x3));
  const sBlind = rng.nextScalar();
  const sCommit = Vesta.add(Vesta.msm(sPoly, g), Vesta.scalarMul(sBlind, w));
  t.commonPoint(sCommit as any);
  const xi = t.squeezeChallenge(),
    z = t.squeezeChallenge();
  let pPrime = sPoly.map((s, i) => Fp.add(Fp.mul(s, xi), pPoly[i]));
  pPrime[0] = Fp.sub(pPrime[0], evalPolynomial(pPrime, x3));
  let f = Fp.add(Fp.mul(sBlind, xi), pBlind);
  let p = pPrime,
    b: bigint[] = [];
  let cur = 1n;
  for (let i = 0; i < n; i++) {
    b.push(cur);
    cur = Fp.mul(cur, x3);
  }
  let gp = g.slice();
  const lr: [{ x: bigint; y: bigint }, { x: bigint; y: bigint }][] = [];
  for (let j = 0; j < k; j++) {
    const half = 1 << (k - j - 1);
    const lBase = Vesta.msm(p.slice(half), gp.slice(0, half)),
      rBase = Vesta.msm(p.slice(0, half), gp.slice(half));
    const vL = innerProd(p.slice(half), b.slice(0, half)),
      vR = innerProd(p.slice(0, half), b.slice(half));
    const lRand = rng.nextScalar(),
      rRand = rng.nextScalar();
    const L = Vesta.add(
      lBase,
      Vesta.add(Vesta.scalarMul(Fp.mul(vL, z), u), Vesta.scalarMul(lRand, w)),
    );
    const R = Vesta.add(
      rBase,
      Vesta.add(Vesta.scalarMul(Fp.mul(vR, z), u), Vesta.scalarMul(rRand, w)),
    );
    lr.push([L as any, R as any]);
    t.commonPoint(L as any);
    t.commonPoint(R as any);
    const uj = t.squeezeChallenge(),
      ujInv = Fp.inv(uj);
    for (let i = 0; i < half; i++) {
      p[i] = Fp.add(p[i], Fp.mul(p[i + half], ujInv));
      b[i] = Fp.add(b[i], Fp.mul(b[i + half], uj));
    }
    p = p.slice(0, half);
    b = b.slice(0, half);
    const ng: { x: bigint; y: bigint }[] = [];
    for (let i = 0; i < half; i++)
      ng.push(Vesta.add(gp[i], Vesta.scalarMul(uj, gp[i + half])) as any);
    gp = ng;
    f = Fp.add(f, Fp.add(Fp.mul(lRand, ujInv), Fp.mul(rRand, uj)));
  }
  return {
    sCommit: sCommit as { x: bigint; y: bigint },
    lr,
    c: p[0],
    f,
    sPolyToWrite: null,
  };
}
function innerProd(a: bigint[], b: bigint[]) {
  let s = 0n;
  for (let i = 0; i < a.length; i++) s = Fp.add(s, Fp.mul(a[i], b[i]));
  return s;
}
