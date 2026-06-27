/**
 * Pure-TS halo2 IPA prover (port of halo2 create_proof, over Vesta). Built and
 * verified step-by-step against a deterministic Rust reference proof (toy circuit,
 * counter RNG). This module accumulates the create_proof pipeline:
 *   advice commit → theta → lookups → beta/gamma → permutation → y → vanishing →
 *   x → evaluations → multiopen → IPA opening.
 */
import { Fp } from './field.js';
import { Vesta, type Point } from './curve.js';
import { omegaForSize } from './fft.js';
import { ZETA } from './domain.js';

/** Fp::DELTA — the permutation argument's coset separator (column j uses δ^j). */
export const DELTA = (() => {
  const h = 'a29b7bdd20cd6c6a3656ee3ef1f3e4f59d04a512715b45bd6cab06000f7d750a';
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
})();

/** Deterministic RNG matching the Rust CounterRng: byte stream 0,1,2,…,255,0,… */
export class CounterRng {
  private ctr = 0;
  /** Next field scalar = Fp.from_uniform_bytes(next 64 counter bytes). */
  nextScalar(): bigint {
    const b = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      b[i] = this.ctr & 0xff;
      this.ctr = (this.ctr + 1) & 0xff;
    }
    return Fp.fromUniformBytes(b);
  }
}

export interface ProvingParams {
  /** Lagrange-basis IPA generators g_lagrange[0..n). */
  gLagrange: { x: bigint; y: bigint }[];
  /** Blinding generator w. */
  w: { x: bigint; y: bigint };
  /** Domain size n = 2^k. */
  n: number;
  /** Number of blinding-factor rows. */
  blindingFactors: number;
}

export interface AdviceCommitResult {
  commitments: Point[];
  blinds: bigint[];
  advice: bigint[][];
}

/**
 * First create_proof step: randomize the blinding rows of each advice column
 * (rows [n-(bf+1), n)), draw a per-column commitment blind, and commit each column
 * in Lagrange basis (Σ aᵢ·g_lagrangeᵢ + blind·w). RNG order matches halo2: all
 * blinding rows first (column-major), then the blinds.
 */
export function commitAdvice(
  params: ProvingParams,
  adviceCols: bigint[][],
  rng: CounterRng,
): AdviceCommitResult {
  const { n, blindingFactors, gLagrange, w } = params;
  const unusableStart = n - (blindingFactors + 1);

  const advice = adviceCols.map((c) => {
    const col = c.map((v) => Fp.mod(v));
    while (col.length < n) col.push(0n);
    return col;
  });
  for (const col of advice) {
    for (let r = unusableStart; r < n; r++) col[r] = rng.nextScalar();
  }
  const blinds = advice.map(() => rng.nextScalar());
  const commitments = advice.map((col, i) =>
    Vesta.add(Vesta.msm(col, gLagrange), Vesta.scalarMul(blinds[i], w)),
  );
  return { commitments, blinds, advice };
}

/**
 * Permutation grand-product polynomial Z for one column chunk (chunk_len=1 here),
 * byte-identical to halo2 permutation::prover. For column j with values `col`,
 * permuted (σ) values `sigma`, and delta power δ^j:
 *   modified[i] = (col[i] + δ^j·ωⁱ·β + γ) / (col[i] + β·σ[i] + γ)
 *   Z[0] = lastZ;  Z[i] = Z[i-1]·modified[i-1]
 * Returns Z (length n); the carry-over lastZ for the next chunk is Z[n-(bf+1)].
 */
export function permutationZ(
  col: bigint[],
  sigma: bigint[],
  beta: bigint,
  gamma: bigint,
  deltaPow: bigint,
  k: number,
  lastZ: bigint,
): bigint[] {
  const n = 1 << k;
  const omega = omegaForSize(k);
  // Denominator col[i] + β·σ[i] + γ, then invert.
  const modified = col.map((v, i) => Fp.add(Fp.add(v, Fp.mul(beta, sigma[i])), gamma));
  for (let i = 0; i < n; i++) modified[i] = Fp.inv(modified[i]);
  // Multiply by numerator col[i] + δ^j·ωⁱ·β + γ.
  let dw = deltaPow;
  for (let i = 0; i < n; i++) {
    modified[i] = Fp.mul(modified[i], Fp.add(Fp.add(Fp.mul(dw, beta), gamma), col[i]));
    dw = Fp.mul(dw, omega);
  }
  // Grand product.
  const z = [lastZ];
  for (let i = 1; i < n; i++) z.push(Fp.mul(z[i - 1], modified[i - 1]));
  return z;
}

/**
 * Commit each permutation grand-product polynomial: overwrite the last
 * `blindingFactors` rows (z[n-bf, n)) with RNG randomness, draw a commitment
 * blind, and commit in Lagrange basis. RNG order (per chunk): bf blinding rows
 * then the blind — matching halo2 permutation::prover. Must continue the same
 * CounterRng used for commitAdvice.
 */
export function commitPermutationZ(
  params: ProvingParams,
  zPolys: bigint[][],
  rng: CounterRng,
): { commitments: Point[]; blindedZ: bigint[][] } {
  const { n, blindingFactors, gLagrange, w } = params;
  const commitments: Point[] = [];
  const blindedZ: bigint[][] = [];
  for (const z of zPolys) {
    const zc = z.slice();
    for (let r = n - blindingFactors; r < n; r++) zc[r] = rng.nextScalar();
    const blind = rng.nextScalar();
    commitments.push(Vesta.add(Vesta.msm(zc, gLagrange), Vesta.scalarMul(blind, w)));
    blindedZ.push(zc);
  }
  return { commitments, blindedZ };
}

/**
 * Vanishing argument's random blinding commitment: a degree n-1 polynomial of RNG
 * coefficients committed in the COEFFICIENT basis (params.commit, gCoeff) plus a
 * random blind. Absorbed before the y challenge. RNG: n coeffs then the blind.
 */
export function commitVanishingRandom(
  gCoeff: { x: bigint; y: bigint }[],
  w: { x: bigint; y: bigint },
  n: number,
  rng: CounterRng,
): { commitment: Point; randomPoly: bigint[] } {
  const coeffs = Array.from({ length: n }, () => rng.nextScalar());
  const blind = rng.nextScalar();
  return {
    commitment: Vesta.add(Vesta.msm(coeffs, gCoeff), Vesta.scalarMul(blind, w)),
    randomPoly: coeffs,
  };
}

/** Evaluate a coefficient polynomial at a point (Horner), halo2 eval_polynomial. */
export function evalPolynomial(coeff: bigint[], point: bigint): bigint {
  let acc = 0n;
  for (let i = coeff.length - 1; i >= 0; i--) acc = Fp.add(Fp.mul(acc, point), coeff[i]);
  return acc;
}

/**
 * Commit the quotient h(X) split into n-sized pieces (coefficient basis), each
 * with an RNG blind. RNG: one blind per piece, continuing the same CounterRng.
 */
export function commitHPieces(
  gCoeff: { x: bigint; y: bigint }[],
  w: { x: bigint; y: bigint },
  hPoly: bigint[],
  n: number,
  rng: CounterRng,
): Point[] {
  const out: Point[] = [];
  for (let off = 0; off < hPoly.length; off += n) {
    const piece = hPoly.slice(off, off + n);
    const blind = rng.nextScalar();
    out.push(Vesta.add(Vesta.msm(piece, gCoeff), Vesta.scalarMul(blind, w)));
  }
  return out;
}

/**
 * Vanishing-argument folded constraint polynomial H on the extended coset
 * (halo2 distribute_powers(expressions, y) then evaluate), for the toy circuit
 * a·b=c with a 3-set permutation. Expression order matches halo2:
 *   gate, perm-first-set, perm-last-set, perm-inter-sets, perm-main-per-set.
 * Folded by Horner with y (first expression gets the highest power).
 */
export interface FoldedHCosets {
  adv0: bigint[];
  adv1: bigint[];
  inst: bigint[];
  sel: bigint[];
  z: bigint[][];
  sigma: bigint[][];
  l0: bigint[];
  lLast: bigint[];
  lBlind: bigint[];
}

export function buildFoldedH(
  c: FoldedHCosets,
  beta: bigint,
  gamma: bigint,
  y: bigint,
  k: number,
  extendedK: number,
  blindingFactors: number,
): bigint[] {
  const extN = 1 << extendedK;
  const omegaExt = omegaForSize(extendedK);
  const rotMul = 1 << (extendedK - k);
  const rotNext = rotMul; // Rotation::next() = +1 row
  const rotLast = -(blindingFactors + 1) * rotMul; // Rotation(-(bf+1))
  const at = (a: bigint[], i: number, shift: number) => a[(((i + shift) % extN) + extN) % extN];
  // X polynomial on the ζ-coset: X[i] = ζ·ω_extⁱ.
  const X: bigint[] = [];
  let wv = ZETA;
  for (let i = 0; i < extN; i++) {
    X.push(wv);
    wv = Fp.mul(wv, omegaExt);
  }
  const cols = [c.adv0, c.adv1, c.inst];
  const exprs: bigint[][] = [];
  const mk = (f: (i: number) => bigint) => Array.from({ length: extN }, (_, i) => f(i));

  // Gate: selector·(adv0·adv1 - adv0@next).
  exprs.push(mk((i) => Fp.mul(c.sel[i], Fp.sub(Fp.mul(c.adv0[i], c.adv1[i]), at(c.adv0, i, rotNext)))));
  // Permutation, first set: (1 - Z_0)·l0.
  exprs.push(mk((i) => Fp.mul(Fp.sub(1n, c.z[0][i]), c.l0[i])));
  // Permutation, last set: (Z_last² - Z_last)·l_last.
  exprs.push(mk((i) => Fp.mul(Fp.sub(Fp.square(c.z[2][i]), c.z[2][i]), c.lLast[i])));
  // Permutation, inter-set: (Z_i - Z_{i-1}@last_rotation)·l0.
  for (let s = 1; s < 3; s++) {
    exprs.push(mk((i) => Fp.mul(Fp.sub(c.z[s][i], at(c.z[s - 1], i, rotLast)), c.l0[i])));
  }
  // Permutation, main identity per set: (left - right)·(1 - (l_last + l_blind)).
  for (let s = 0; s < 3; s++) {
    const col = cols[s];
    const sig = c.sigma[s];
    const cd0 = Fp.mul(beta, Fp.pow(DELTA, BigInt(s)));
    exprs.push(
      mk((i) => {
        const left = Fp.mul(at(c.z[s], i, rotNext), Fp.add(Fp.add(col[i], Fp.mul(beta, sig[i])), gamma));
        const right = Fp.mul(c.z[s][i], Fp.add(Fp.add(col[i], Fp.mul(cd0, X[i])), gamma));
        return Fp.mul(Fp.sub(left, right), Fp.sub(1n, Fp.add(c.lLast[i], c.lBlind[i])));
      }),
    );
  }
  // Fold by Horner: acc = acc·y + e (first expression highest power).
  const H = new Array<bigint>(extN).fill(0n);
  for (const e of exprs) for (let i = 0; i < extN; i++) H[i] = Fp.add(Fp.mul(H[i], y), e[i]);
  return H;
}

/** Inner product Σ aᵢ·bᵢ over Fp. */
function innerProduct(a: bigint[], b: bigint[]): bigint {
  let acc = 0n;
  for (let i = 0; i < a.length; i++) acc = Fp.add(acc, Fp.mul(a[i], b[i]));
  return acc;
}

/**
 * IPA opening (halo2 poly/commitment/prover.rs create_proof) for polynomial
 * `pPoly` (n coeffs), blind `pBlind`, opened at `x3`. Generators g (coeff basis),
 * w (blinding), u (inner-product). Challenges xi/z and the per-round u_j are taken
 * from the transcript (passed in). RNG (continuing the prover's CounterRng):
 * s_poly (n coeffs), s_blind, then per round l_rand, r_rand.
 */
export function buildIPA(
  pPoly: bigint[],
  pBlind: bigint,
  x3: bigint,
  g: { x: bigint; y: bigint }[],
  w: { x: bigint; y: bigint },
  u: { x: bigint; y: bigint },
  xi: bigint,
  z: bigint,
  uChallenges: bigint[],
  rng: CounterRng,
  k: number,
): { sCommit: Point; lr: [Point, Point][]; c: bigint; f: bigint } {
  const n = 1 << k;
  // Random s(X) with a root at x3.
  const sPoly = Array.from({ length: n }, () => rng.nextScalar());
  sPoly[0] = Fp.sub(sPoly[0], evalPolynomial(sPoly, x3));
  const sBlind = rng.nextScalar();
  const sCommit = Vesta.add(Vesta.msm(sPoly, g), Vesta.scalarMul(sBlind, w));

  // P' = ξ·s + p, rooted at x3.
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

  const lr: [Point, Point][] = [];
  for (let j = 0; j < k; j++) {
    const half = 1 << (k - j - 1);
    const lBase = Vesta.msm(p.slice(half), gp.slice(0, half));
    const rBase = Vesta.msm(p.slice(0, half), gp.slice(half));
    const vL = innerProduct(p.slice(half), b.slice(0, half));
    const vR = innerProduct(p.slice(0, half), b.slice(half));
    const lRand = rng.nextScalar();
    const rRand = rng.nextScalar();
    const lj = Vesta.add(
      lBase,
      Vesta.add(Vesta.scalarMul(Fp.mul(vL, z), u), Vesta.scalarMul(lRand, w)),
    );
    const rj = Vesta.add(
      rBase,
      Vesta.add(Vesta.scalarMul(Fp.mul(vR, z), u), Vesta.scalarMul(rRand, w)),
    );
    lr.push([lj, rj]);

    const uj = uChallenges[j];
    const ujInv = Fp.inv(uj);
    for (let i = 0; i < half; i++) {
      p[i] = Fp.add(p[i], Fp.mul(p[i + half], ujInv));
      b[i] = Fp.add(b[i], Fp.mul(b[i + half], uj));
    }
    p = p.slice(0, half);
    b = b.slice(0, half);
    const ng: Point[] = [];
    for (let i = 0; i < half; i++) ng.push(Vesta.add(gp[i], Vesta.scalarMul(uj, gp[i + half])));
    gp = ng as { x: bigint; y: bigint }[];
    f = Fp.add(f, Fp.add(Fp.mul(lRand, ujInv), Fp.mul(rRand, uj)));
  }
  return { sCommit, lr, c: p[0], f };
}

/** Divide a(X) by (X - point), dropping the remainder (halo2 kate_division). */
export function kateDivision(a: bigint[], point: bigint): bigint[] {
  const b = Fp.sub(0n, point);
  const lenQ = a.length - 1;
  const q = new Array<bigint>(lenQ).fill(0n);
  let tmp = 0n;
  for (let k = 0; k < lenQ; k++) {
    const lead = Fp.sub(a[a.length - 1 - k], tmp);
    q[lenQ - 1 - k] = lead;
    tmp = Fp.mul(lead, b);
  }
  return q;
}

export interface MultiopenSet {
  /** Polynomials (coeff) opened at this point set, in accumulation order. */
  polys: bigint[][];
  /** The point set (rotations) these polynomials are opened at. */
  points: bigint[];
}

/**
 * Multiopen (halo2 poly/multiopen/prover.rs): collapse each point set's polys with
 * x1, divide by (X-point) per point and fold with x2 → q_prime; q evals at x3; the
 * final p(X) = fold(q_prime, q_polys; x4) is the IPA opening input.
 */
export function buildMultiopen(
  sets: MultiopenSet[],
  x1: bigint,
  x2: bigint,
  x3: bigint,
  x4: bigint,
  n: number,
): { qPrime: bigint[]; qEvals: bigint[]; pPoly: bigint[]; qPolys: bigint[][] } {
  const qPolys = sets.map((s) =>
    s.polys.reduce<bigint[] | null>(
      (q, p) => (q === null ? p.slice() : q.map((v, i) => Fp.add(Fp.mul(v, x1), p[i]))),
      null,
    )!,
  );
  let qPrime: bigint[] | null = null;
  sets.forEach((s, si) => {
    let poly = qPolys[si].slice();
    for (const point of s.points) poly = kateDivision(poly, point);
    while (poly.length < n) poly.push(0n);
    qPrime = qPrime === null ? poly : qPrime.map((v, i) => Fp.add(Fp.mul(v, x2), poly[i]));
  });
  const qEvals = qPolys.map((q) => evalPolynomial(q, x3));
  let pPoly = qPrime!.slice();
  for (const q of qPolys) pPoly = pPoly.map((v, i) => Fp.add(Fp.mul(v, x4), q[i]));
  return { qPrime: qPrime!, qEvals, pPoly, qPolys };
}

/**
 * Lookup permute (halo2 permute_expression_pair): A' = sorted input; S' has the
 * first row of each like-input-run equal to the input value, remaining rows filled
 * with leftover table values (BTreeMap key order = canonical ascending). Then bf+1
 * blinding rows each (RNG: input blinds then table blinds).
 */
export function permuteExpressionPair(
  input: bigint[],
  table: bigint[],
  usableRows: number,
  bf: number,
  rng: CounterRng,
): { pInput: bigint[]; pTable: bigint[] } {
  const cmp = (a: bigint, b: bigint) => (a < b ? -1 : a > b ? 1 : 0);
  const pInput = input.slice(0, usableRows).sort(cmp);
  const counts = new Map<bigint, number>();
  for (let i = 0; i < usableRows; i++) counts.set(table[i], (counts.get(table[i]) ?? 0) + 1);
  const pTable = new Array<bigint>(usableRows).fill(0n);
  const repeated: number[] = [];
  for (let row = 0; row < usableRows; row++) {
    if (row === 0 || pInput[row] !== pInput[row - 1]) {
      pTable[row] = pInput[row];
      counts.set(pInput[row], counts.get(pInput[row])! - 1);
    } else {
      repeated.push(row);
    }
  }
  for (const coeff of [...counts.keys()].sort(cmp)) {
    for (let c = 0; c < counts.get(coeff)!; c++) pTable[repeated.pop()!] = coeff;
  }
  for (let i = 0; i < bf + 1; i++) pInput.push(rng.nextScalar());
  for (let i = 0; i < bf + 1; i++) pTable.push(rng.nextScalar());
  return { pInput, pTable };
}

/**
 * Lookup grand-product Z (halo2 lookup::commit_product). With compressed input
 * `cin`, table `ctab`, and permuted A'/S':
 *   lp[i] = (cin[i]+β)(ctab[i]+γ) / ((A'[i]+β)(S'[i]+γ))
 *   Z[0]=1, Z[i+1]=Z[i]·lp[i]; first n-bf rows are the running product, last bf
 *   rows are RNG blinds; then a commitment blind. (n-bf-1 products are computed.)
 */
export function commitLookupProduct(
  cin: bigint[],
  ctab: bigint[],
  pInput: bigint[],
  pTable: bigint[],
  beta: bigint,
  gamma: bigint,
  params: ProvingParams,
  rng: CounterRng,
): { commitment: Point; zPoly: bigint[] } {
  const { n, blindingFactors, gLagrange, w } = params;
  const lp = new Array<bigint>(n);
  for (let i = 0; i < n; i++) lp[i] = Fp.mul(Fp.add(beta, pInput[i]), Fp.add(gamma, pTable[i]));
  for (let i = 0; i < n; i++) lp[i] = Fp.inv(lp[i]);
  for (let i = 0; i < n; i++)
    lp[i] = Fp.mul(lp[i], Fp.mul(Fp.add(cin[i], beta), Fp.add(ctab[i], gamma)));
  const z = [1n];
  for (let i = 0; i < n - blindingFactors - 1; i++) z.push(Fp.mul(z[z.length - 1], lp[i]));
  for (let i = 0; i < blindingFactors; i++) z.push(rng.nextScalar());
  const blind = rng.nextScalar();
  return { commitment: Vesta.add(Vesta.msm(z, gLagrange), Vesta.scalarMul(blind, w)), zPoly: z };
}

/**
 * The five lookup constraint polynomials on the extended coset (halo2
 * lookup::construct), given cosets of Z_lookup, A', S', and compressed input/table:
 *   l0·(1-Z), l_last·(Z²-Z),
 *   active·(Z(ωX)(A'+β)(S'+γ) - Z(X)(cin+β)(ctab+γ)),
 *   l0·(A'-S'), active·(A'-S')(A'-A'(ω⁻¹X))   where active = 1-(l_last+l_blind).
 */
export function buildLookupExpressions(
  c: {
    z: bigint[];
    ap: bigint[];
    sp: bigint[];
    cin: bigint[];
    ctab: bigint[];
    l0: bigint[];
    lLast: bigint[];
    lBlind: bigint[];
  },
  beta: bigint,
  gamma: bigint,
  k: number,
  extendedK: number,
): bigint[][] {
  const extN = 1 << extendedK;
  const rotMul = 1 << (extendedK - k);
  const at = (a: bigint[], i: number, shift: number) => a[(((i + shift) % extN) + extN) % extN];
  const active = (i: number) => Fp.sub(1n, Fp.add(c.lLast[i], c.lBlind[i]));
  const mk = (f: (i: number) => bigint) => Array.from({ length: extN }, (_, i) => f(i));
  return [
    mk((i) => Fp.mul(Fp.sub(1n, c.z[i]), c.l0[i])),
    mk((i) => Fp.mul(Fp.sub(Fp.square(c.z[i]), c.z[i]), c.lLast[i])),
    mk((i) => {
      const left = Fp.mul(
        Fp.mul(at(c.z, i, rotMul), Fp.add(c.ap[i], beta)),
        Fp.add(c.sp[i], gamma),
      );
      const right = Fp.mul(
        Fp.mul(c.z[i], Fp.add(c.cin[i], beta)),
        Fp.add(c.ctab[i], gamma),
      );
      return Fp.mul(Fp.sub(left, right), active(i));
    }),
    mk((i) => Fp.mul(Fp.sub(c.ap[i], c.sp[i]), c.l0[i])),
    mk((i) => Fp.mul(Fp.mul(Fp.sub(c.ap[i], c.sp[i]), Fp.sub(c.ap[i], at(c.ap, i, -rotMul))), active(i))),
  ];
}
