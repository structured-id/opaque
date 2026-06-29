/**
 * Pure-TS halo2 IPA create_proof for the ZkppCircuit (k=11), byte-exact vs the Rust
 * prover (verified in tests/zkpp-fullproof.test.ts: 12352-byte proof, accepted by
 * Rust verify_proof). Takes the assembled advice witness (see circuit/witness.ts)
 * plus the circuit params and emits the proof bytes, reporting progress per stage
 * for a UI gauge.
 *
 * RNG is the deterministic CounterRng(0); the single transcript threads every stage
 * in halo2 order. Blinding offsets (318/383/460/508/2587/2588) match create_proof's
 * exact CounterRng consumption order.
 */
import { Fp } from "./field.js";
import { Vesta } from "./curve.js";
import { Transcript } from "./transcript.js";
import {
  lagrangeToCoeff,
  coeffToExtended,
  extendedToCoeff,
  vanishingTInv,
  divideByVanishing,
} from "./domain.js";
import { compileAst, type Ast, type EvalCtx } from "./gate-eval.js";
import {
  CounterRng,
  evalPolynomial,
  permutationZChunk,
  kateDivision,
  permuteExpressionPair,
  type MultiopenSet,
} from "./prover.js";
import { ProgressTracker, type ZkppProgress } from "./progress.js";
import { WorkerPool, hwConcurrency } from "./worker-pool.js";

type Pt = { x: bigint; y: bigint };

export interface Query {
  col: number;
  rot: number;
}

/** Fixed circuit params (SRS + proving key + constraint system) for k=11. */
export interface ProverParams {
  gLagrange: Pt[];
  gCoeff: Pt[];
  w: Pt;
  u: Pt;
  fixed: bigint[][];
  sigmas: bigint[][];
  vkRepr: bigint;
  gates: Ast[];
  lkin: Ast[][];
  lktab: Ast[][];
  permMap: { col: number; ty: string }[];
  aq: Query[];
  fq: Query[];
  iq: Query[];
  l0: bigint[];
  lLast: bigint[];
  lBlind: bigint[];
  xc: bigint[];
  omega: bigint;
  delta: bigint;
}

export interface CreateProofOptions {
  onProgress?: (p: ZkppProgress) => void;
  /** Run the embarrassingly-parallel stages (commits, cosets) on a worker pool. */
  workers?: boolean;
  /** Override the worker-pool size; defaults to detected hardware concurrency. */
  maxWorkers?: number;
}

const N = 2048;
const K = 11;
const EXTK = 14;
const EXTN = 1 << EXTK;
const QPD = EXTN / N;
const BF = 5;

const innerProd = (a: bigint[], b: bigint[]): bigint => {
  let s = 0n;
  for (let i = 0; i < a.length; i++) s = Fp.add(s, Fp.mul(a[i], b[i]));
  return s;
};

/**
 * Run the IPA opening for `pPoly` at the evaluation point series `x3`: commit the
 * synthetic blinding poly, squeeze xi/z, then k rounds of L/R folds. Returns the
 * commitments and the final scalars c, f.
 */
function runIPA(
  t: Transcript,
  pPoly: bigint[],
  pBlind: bigint,
  x3: bigint,
  g: Pt[],
  w: Pt,
  u: Pt,
  rng: CounterRng,
): { sCommit: Pt; lr: [Pt, Pt][]; c: bigint; f: bigint } {
  const n = pPoly.length;
  const k = Math.log2(n);
  const sPoly = Array.from({ length: n }, () => rng.nextScalar());
  sPoly[0] = Fp.sub(sPoly[0], evalPolynomial(sPoly, x3));
  const sBlind = rng.nextScalar();
  const sCommit = Vesta.add(
    Vesta.msm(sPoly, g),
    Vesta.scalarMul(sBlind, w),
  ) as Pt;
  t.commonPoint(sCommit);
  const xi = t.squeezeChallenge();
  const z = t.squeezeChallenge();
  const pPrime = sPoly.map((s, i) => Fp.add(Fp.mul(s, xi), pPoly[i]));
  pPrime[0] = Fp.sub(pPrime[0], evalPolynomial(pPrime, x3));
  let f = Fp.add(Fp.mul(sBlind, xi), pBlind);
  let p = pPrime;
  let b: bigint[] = [];
  let cur = 1n;
  for (let i = 0; i < n; i++) {
    b.push(cur);
    cur = Fp.mul(cur, x3);
  }
  let gp = g.slice();
  const lr: [Pt, Pt][] = [];
  for (let j = 0; j < k; j++) {
    const half = 1 << (k - j - 1);
    const lBase = Vesta.msm(p.slice(half), gp.slice(0, half));
    const rBase = Vesta.msm(p.slice(0, half), gp.slice(half));
    const vL = innerProd(p.slice(half), b.slice(0, half));
    const vR = innerProd(p.slice(0, half), b.slice(half));
    const lRand = rng.nextScalar();
    const rRand = rng.nextScalar();
    const L = Vesta.add(
      lBase,
      Vesta.add(Vesta.scalarMul(Fp.mul(vL, z), u), Vesta.scalarMul(lRand, w)),
    ) as Pt;
    const R = Vesta.add(
      rBase,
      Vesta.add(Vesta.scalarMul(Fp.mul(vR, z), u), Vesta.scalarMul(rRand, w)),
    ) as Pt;
    lr.push([L, R]);
    t.commonPoint(L);
    t.commonPoint(R);
    const uj = t.squeezeChallenge();
    const ujInv = Fp.inv(uj);
    for (let i = 0; i < half; i++) {
      p[i] = Fp.add(p[i], Fp.mul(p[i + half], ujInv));
      b[i] = Fp.add(b[i], Fp.mul(b[i + half], uj));
    }
    p = p.slice(0, half);
    b = b.slice(0, half);
    const ng: Pt[] = [];
    for (let i = 0; i < half; i++)
      ng.push(Vesta.add(gp[i], Vesta.scalarMul(uj, gp[i + half])) as Pt);
    gp = ng;
    f = Fp.add(f, Fp.add(Fp.mul(lRand, ujInv), Fp.mul(rRand, uj)));
  }
  return { sCommit, lr, c: p[0], f };
}

/**
 * Produce the ZkppCircuit proof (12352 bytes) for the given advice witness and
 * instance column. Byte-exact vs Rust create_proof.
 */
export async function createProof(
  advice: bigint[][],
  instanceCol: bigint[],
  params: ProverParams,
  opts: CreateProofOptions = {},
): Promise<Uint8Array> {
  const {
    gLagrange: gL,
    gCoeff: gC,
    w,
    u,
    fixed,
    sigmas,
    vkRepr,
    gates,
    lkin,
    lktab,
    permMap,
    aq,
    fq,
    iq,
    l0,
    lLast,
    lBlind,
    xc: XC,
    omega,
    delta,
  } = params;
  const instance = [instanceCol];
  const prog = new ProgressTracker(opts.onProgress);
  // Worker-pool size: detected cores when workers are enabled, else single-thread
  // (inline). Commits and cosets are pure (no RNG) and independent, so running them
  // on the pool is byte-identical to sequential — only faster.
  const poolSize = opts.workers ? (opts.maxWorkers ?? hwConcurrency()) : 1;
  // Persistent pools: spawned + (for commits) SRS-initialised ONCE, then reused
  // across every stage (the 3 coset maps + commits) so worker spawn / module load /
  // SRS init is paid once, not per stage. Not usable (Node, single core) -> inline.
  const cosetPool = new WorkerPool(
    new URL("./coset-worker.js", import.meta.url),
    poolSize,
  );
  const commitPool = new WorkerPool(
    new URL("./commit-worker.js", import.meta.url),
    poolSize,
    { gL, w },
  );

  const out: number[] = [];
  const pushPt = (p: Pt): void => {
    out.push(...Vesta.toBytes(p));
  };
  const pushSc = (v: bigint): void => {
    out.push(...Fp.toBytes(v));
  };

  const rng = new CounterRng();
  const t = new Transcript();
  const ctx: EvalCtx = { advice, fixed, instance, n: N };
  t.commonScalar(vkRepr);
  // instance commit (Blind::default = ONE), absorbed not written.
  t.commonPoint(
    Vesta.add(Vesta.msm(instanceCol, gL), Vesta.scalarMul(1n, w)) as Pt,
  );

  // stage 1: advice commits (53). RNG: 53*6 blinding rows (col-major) then 53 blinds.
  prog.report("commit-advice", 0);
  const adviceBlinds: bigint[] = [];
  for (let c = 0; c < 53; c++)
    for (let r = N - 6; r < N; r++) advice[c][r] = rng.nextScalar();
  for (let c = 0; c < 53; c++) adviceBlinds.push(rng.nextScalar());
  // Commit the 53 advice columns on the (SRS-initialised) MSM pool — tiny 1-point
  // output, near-linear scaling — then absorb in order. Node: inline (byte-identical).
  const adviceCommits = await commitPool.map(
    Array.from({ length: 53 }, (_, c) => c),
    (c) =>
      Vesta.add(
        Vesta.msm(advice[c], gL),
        Vesta.scalarMul(adviceBlinds[c], w),
      ) as Pt,
    (c) => ({ poly: advice[c], blind: adviceBlinds[c] }),
    (m) => m as Pt,
    (d, n) => prog.report("commit-advice", d / n),
  );
  for (let c = 0; c < 53; c++) {
    pushPt(adviceCommits[c]);
    t.commonPoint(adviceCommits[c]);
  }
  const theta = t.squeezeChallenge();

  // stage 3: lookup compress + permute + commit (12).
  prog.report("lookups", 0);
  const compress = (exprs: Ast[]): bigint[] => {
    const fns = exprs.map((e) => compileAst(e, 1, N));
    return Array.from({ length: N }, (_, r) => {
      let a = 0n;
      for (const f of fns) a = Fp.add(Fp.mul(a, theta), f(r, ctx));
      return a;
    });
  };
  const cins: bigint[][] = [];
  const ctabs: bigint[][] = [];
  const aps: bigint[][] = [];
  const sps: bigint[][] = [];
  const apCommits: Pt[] = [];
  const spCommits: Pt[] = [];
  for (let lp = 0; lp < 6; lp++) {
    const cin = compress(lkin[lp]);
    const ctab = compress(lktab[lp]);
    const { pInput: ap, pTable: sp } = permuteExpressionPair(
      cin,
      ctab,
      N - (BF + 1),
      BF,
      rng,
    );
    const apBlind = rng.nextScalar();
    const spBlind = rng.nextScalar();
    cins.push(cin);
    ctabs.push(ctab);
    aps.push(ap);
    sps.push(sp);
    apCommits.push(
      Vesta.add(Vesta.msm(ap, gL), Vesta.scalarMul(apBlind, w)) as Pt,
    );
    spCommits.push(
      Vesta.add(Vesta.msm(sp, gL), Vesta.scalarMul(spBlind, w)) as Pt,
    );
  }
  for (let lp = 0; lp < 6; lp++) {
    for (const p of [apCommits[lp], spCommits[lp]]) {
      pushPt(p);
      t.commonPoint(p);
    }
  }
  const beta = t.squeezeChallenge();
  const gamma = t.squeezeChallenge();

  // stage 5: permutation grand-product Z (8 chunks) + commits.
  prog.report("permutation", 0);
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
    const cols = permCol.slice(c * 7, c * 7 + 7);
    const sig = sigmas.slice(c * 7, c * 7 + 7);
    const dps = dpow.slice(c * 7, c * 7 + 7);
    const z = permutationZChunk(cols, sig, dps, beta, gamma, K, lastZ);
    lastZ = z[N - 6];
    permZ.push(z);
  }
  for (let c = 0; c < 8; c++) {
    for (let r = N - 5; r < N; r++) permZ[c][r] = rng.nextScalar();
    const bl = rng.nextScalar();
    const p = Vesta.add(Vesta.msm(permZ[c], gL), Vesta.scalarMul(bl, w)) as Pt;
    pushPt(p);
    t.commonPoint(p);
  }
  // lookup grand-product Z (6) + commits.
  const lookZ: bigint[][] = [];
  for (let lp = 0; lp < 6; lp++) {
    const lpr = Array.from({ length: N }, (_, i) =>
      Fp.mul(
        Fp.mul(Fp.add(cins[lp][i], beta), Fp.add(ctabs[lp][i], gamma)),
        Fp.inv(Fp.mul(Fp.add(aps[lp][i], beta), Fp.add(sps[lp][i], gamma))),
      ),
    );
    const z = new Array<bigint>(N).fill(0n);
    z[0] = 1n;
    for (let i = 1; i < N - 5; i++) z[i] = Fp.mul(z[i - 1], lpr[i - 1]);
    for (let i = N - 5; i < N; i++) z[i] = rng.nextScalar();
    const bl = rng.nextScalar();
    lookZ.push(z);
    const p = Vesta.add(Vesta.msm(z, gL), Vesta.scalarMul(bl, w)) as Pt;
    pushPt(p);
    t.commonPoint(p);
  }
  // vanishing random poly + commit.
  const randomPoly = Array.from({ length: N }, () => rng.nextScalar());
  const randomBlind = rng.nextScalar();
  {
    const p = Vesta.add(
      Vesta.msm(randomPoly, gC),
      Vesta.scalarMul(randomBlind, w),
    ) as Pt;
    pushPt(p);
    t.commonPoint(p);
  }
  const y = t.squeezeChallenge();

  // stage 6: quotient h over the extended domain.
  prog.report("quotient", 0);
  const toCos = (col: bigint[]): bigint[] =>
    coeffToExtended(lagrangeToCoeff(col, K), EXTK);
  // The bulk of the coset FFTs (advice 53 + fixed 55 + sigma 56) are independent
  // and pure — run them on the SAME persistent pool across all three batches (each
  // FFT a Web Worker in the browser; inline in Node, byte-identical).
  const cTo = (col: bigint[]): unknown => col;
  const cFrom = (m: unknown): bigint[] => m as bigint[];
  const adviceCos = await cosetPool.map(advice, toCos, cTo, cFrom);
  const fixedCos = await cosetPool.map(fixed, toCos, cTo, cFrom);
  const instCos = instance.map(toCos);
  const cosCtx: EvalCtx = {
    advice: adviceCos,
    fixed: fixedCos,
    instance: instCos,
    n: EXTN,
    rotScale: QPD,
  };
  const sigCos = await cosetPool.map(sigmas, toCos, cTo, cFrom);
  const permColCos = permMap.map((m) =>
    m.ty === "Advice"
      ? adviceCos[m.col]
      : m.ty === "Fixed"
        ? fixedCos[m.col]
        : instCos[m.col],
  );
  const permZCos = permZ.map(toCos);
  const apCos = aps.map(toCos);
  const spCos = sps.map(toCos);
  const lookZCos = lookZ.map(toCos);
  const compressCos = (exprs: Ast[]): bigint[] => {
    const fns = exprs.map((ex) => compileAst(ex, QPD, EXTN));
    return Array.from({ length: EXTN }, (_, j) => {
      let a = 0n;
      for (const f of fns) a = Fp.add(Fp.mul(a, theta), f(j, cosCtx));
      return a;
    });
  };
  const cinCos = lkin.map(compressCos);
  const ctabCos = lktab.map(compressCos);
  const rot = (a: bigint[], j: number, sh: number): bigint =>
    a[(((j + sh) % EXTN) + EXTN) % EXTN];
  const gateFns = gates.map((g) => compileAst(g, QPD, EXTN));
  const folded = new Array<bigint>(EXTN);
  for (let j = 0; j < EXTN; j++) {
    let acc = 0n;
    for (const gf of gateFns) acc = Fp.add(Fp.mul(acc, y), gf(j, cosCtx));
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
      let left = rot(permZCos[c], j, QPD);
      let right = permZCos[c][j];
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
    for (let lp = 0; lp < 6; lp++) {
      const z = lookZCos[lp];
      const A = apCos[lp];
      const S = spCos[lp];
      const cin = cinCos[lp];
      const ctab = ctabCos[lp];
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
            Fp.mul(Fp.mul(z[j], Fp.add(cin[j], beta)), Fp.add(ctab[j], gamma)),
          ),
        ),
        Fp.mul(l0[j], Fp.sub(A[j], S[j])),
        Fp.mul(Fp.mul(act, Fp.sub(A[j], S[j])), Fp.sub(A[j], rot(A, j, -QPD))),
      ];
      for (const e of le) acc = Fp.add(Fp.mul(acc, y), e);
    }
    folded[j] = acc;
    if ((j & 4095) === 0) prog.report("quotient", j / EXTN);
  }
  const hCoeff = extendedToCoeff(
    divideByVanishing(folded, vanishingTInv(K, EXTK)),
    K,
    EXTK,
    QPD,
  );
  for (let p = 0; p < 8; p++) {
    const piece = hCoeff.slice(p * N, (p + 1) * N);
    const bl = rng.nextScalar();
    const pt = Vesta.add(Vesta.msm(piece, gC), Vesta.scalarMul(bl, w)) as Pt;
    pushPt(pt);
    t.commonPoint(pt);
  }
  const x = t.squeezeChallenge();

  // stage 7: evaluations.
  prog.report("evaluate", 0);
  const xrot = (r: number): bigint =>
    Fp.mul(x, Fp.pow(omega, BigInt(((r % N) + N) % N)));
  const adviceCoeff = advice.map((c) => lagrangeToCoeff(c, K));
  const fixedCoeff = fixed.map((c) => lagrangeToCoeff(c, K));
  const instCoeff = instance.map((c) => lagrangeToCoeff(c, K));
  const sigCoeff = sigmas.map((c) => lagrangeToCoeff(c, K));
  const permZCoeff = permZ.map((z) => lagrangeToCoeff(z, K));
  const lookZCoeff = lookZ.map((z) => lagrangeToCoeff(z, K));
  const apCoeff = aps.map((a) => lagrangeToCoeff(a, K));
  const spCoeff = sps.map((s) => lagrangeToCoeff(s, K));
  const writeEval = (v: bigint): void => {
    pushSc(v);
    t.commonScalar(v);
  };
  for (const q of iq) writeEval(evalPolynomial(instCoeff[q.col], xrot(q.rot)));
  for (const q of aq)
    writeEval(evalPolynomial(adviceCoeff[q.col], xrot(q.rot)));
  for (const q of fq) writeEval(evalPolynomial(fixedCoeff[q.col], xrot(q.rot)));
  writeEval(evalPolynomial(randomPoly, x));
  for (let j = 0; j < 56; j++) writeEval(evalPolynomial(sigCoeff[j], x));
  const xw = xrot(1);
  const xLastP = xrot(-6);
  const xInv = xrot(-1);
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

  // stage 8: multiopen.
  prog.report("multiopen", 0);
  const x1 = t.squeezeChallenge();
  const x2 = t.squeezeChallenge();
  const xn = Fp.pow(x, BigInt(N));
  const hCombined = new Array<bigint>(N).fill(0n);
  let xnk = 1n;
  for (let k = 0; k < 8; k++) {
    for (let i = 0; i < N; i++)
      hCombined[i] = Fp.add(hCombined[i], Fp.mul(hCoeff[k * N + i], xnk));
    xnk = Fp.mul(xnk, xn);
  }
  interface Qd {
    id: string;
    poly: bigint[];
    point: bigint;
  }
  const queries: Qd[] = [];
  for (const q of iq)
    queries.push({
      id: `i${q.col}`,
      poly: instCoeff[q.col],
      point: xrot(q.rot),
    });
  for (const q of aq)
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
  for (const q of fq)
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
  const pointIdx = new Map<bigint, number>();
  const commits = new Map<string, { poly: bigint[]; pts: number[] }>();
  for (const q of queries) {
    if (!pointIdx.has(q.point)) pointIdx.set(q.point, pointIdx.size);
    const pi = pointIdx.get(q.point)!;
    if (!commits.has(q.id)) commits.set(q.id, { poly: q.poly, pts: [] });
    commits.get(q.id)!.pts.push(pi);
  }
  const invPt = new Map<number, bigint>();
  for (const [pt, i] of pointIdx) invPt.set(i, pt);
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
    sets[si].points = key.split(",").map((n) => invPt.get(+n)!);
  const commitOrder: { id: string; setIdx: number }[] = [];
  for (const [id, d] of commits) {
    const si = setIdx.get(commitSet.get(id)!.join(","))!;
    sets[si].polys.push(d.poly);
    commitOrder.push({ id, setIdx: si });
  }
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
  const qpBlind = rng.nextScalar();
  {
    const p = Vesta.add(
      Vesta.msm(qPrime!, gC),
      Vesta.scalarMul(qpBlind, w),
    ) as Pt;
    pushPt(p);
    t.commonPoint(p);
  }
  const x3 = t.squeezeChallenge();
  for (const q of qPolys) writeEval(evalPolynomial(q, x3));
  const x4 = t.squeezeChallenge();
  let pPoly = qPrime!.slice();
  for (const q of qPolys)
    pPoly = pPoly.map((v, i) => Fp.add(Fp.mul(v, x4), q[i]));
  // p_blind: recombine per-commitment blinds in (x1, x4) order.
  const rngAt = (k: number): bigint => {
    const r = new CounterRng();
    for (let i = 0; i < k; i++) r.nextScalar();
    return r.nextScalar();
  };
  let hBlind = 0n;
  let hxnk = 1n;
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
  const qBlinds = new Array<bigint>(sets.length).fill(0n);
  for (const { id, setIdx: si } of commitOrder)
    qBlinds[si] = Fp.add(Fp.mul(qBlinds[si], x1), blindOf(id));
  let pBlind = qpBlind;
  for (const qb of qBlinds) pBlind = Fp.add(Fp.mul(pBlind, x4), qb);

  // IPA opening.
  prog.report("ipa", 0);
  const { sCommit, lr, c, f } = runIPA(t, pPoly, pBlind, x3, gC, w, u, rng);
  pushPt(sCommit);
  for (const [L, R] of lr) {
    pushPt(L);
    pushPt(R);
  }
  pushSc(c);
  pushSc(f);
  cosetPool.terminate();
  commitPool.terminate();
  prog.done();
  return Uint8Array.from(out);
}
