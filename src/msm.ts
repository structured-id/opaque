/**
 * Batched point arithmetic on y² = x³ + b (both Pasta curves) over a base
 * field `F`:
 *
 * - {@link batchAffine}: many independent affine additions or doublings
 *   sharing one field inversion (Montgomery's trick), about six
 *   multiplications per operation instead of one inversion each;
 * - {@link msm}: Pippenger with signed windows, the buckets filled with
 *   batched affine additions, the window sums in Jacobian coordinates;
 * - {@link mulEach}: many points each times its own scalar, in lockstep, so
 *   every doubling and addition step is one batch.
 *
 * All of it computes the same group elements as the textbook formulas: only
 * the cost changes, never a proof byte.
 */
import type { Field } from "./field.js";

export interface Affine {
  x: bigint;
  y: bigint;
}

/**
 * Points held as parallel coordinate arrays, `inf[i] = 1` marking the
 * identity (its coordinates are then meaningless).
 */
export interface Points {
  x: bigint[];
  y: bigint[];
  inf: Uint8Array;
}

/**
 * For each k < count, `R[t[k]] += Q_k` (or `R[t[k]] = 2·R[t[k]]` when `qx`
 * is null), all targets distinct. Degenerate cases (identity, equal points,
 * opposite points) are handled exactly; the curve has odd order, so a
 * doubling never meets y = 0.
 */
export function batchAffine(
  F: Field,
  r: Points,
  t: ArrayLike<number>,
  count: number,
  qx: bigint[] | null,
  qy: bigint[] | null,
): void {
  // Active operations, compacted: target, addend x (or the target's own x
  // for a doubling), numerator and denominator of the slope.
  const at = new Int32Array(count);
  const ax = new Array<bigint>(count);
  const num = new Array<bigint>(count);
  const den = new Array<bigint>(count);
  let n = 0;
  for (let k = 0; k < count; k++) {
    const i = t[k];
    if (r.inf[i]) {
      if (qx === null) continue;
      r.x[i] = qx[k];
      r.y[i] = (qy as bigint[])[k];
      r.inf[i] = 0;
      continue;
    }
    const xi = r.x[i];
    const yi = r.y[i];
    if (qx !== null) {
      const x2 = qx[k];
      const y2 = (qy as bigint[])[k];
      if (xi !== x2) {
        at[n] = i;
        ax[n] = x2;
        num[n] = F.sub(y2, yi);
        den[n] = F.sub(x2, xi);
        n++;
        continue;
      }
      if (yi !== y2) {
        r.inf[i] = 1;
        continue;
      }
    }
    const xx = F.square(xi);
    at[n] = i;
    ax[n] = xi;
    num[n] = F.add(F.add(xx, xx), xx);
    den[n] = F.add(yi, yi);
    n++;
  }
  if (n === 0) return;
  // Montgomery's trick: prefix products, one inversion, peel back.
  const pre = new Array<bigint>(n);
  let acc = den[0];
  pre[0] = acc;
  for (let j = 1; j < n; j++) {
    acc = F.mul(acc, den[j]);
    pre[j] = acc;
  }
  let inv = F.inv(acc);
  for (let j = n - 1; j >= 0; j--) {
    const denInv = j === 0 ? inv : F.mul(inv, pre[j - 1]);
    if (j > 0) inv = F.mul(inv, den[j]);
    const i = at[j];
    const x1 = r.x[i];
    const lambda = F.mul(num[j], denInv);
    const x3 = F.sub(F.sub(F.square(lambda), x1), ax[j]);
    r.y[i] = F.sub(F.mul(lambda, F.sub(x1, x3)), r.y[i]);
    r.x[i] = x3;
  }
}

/** Jacobian point (X/Z², Y/Z³); Z = 0 is the identity. */
interface Jacobian {
  x: bigint;
  y: bigint;
  z: bigint;
}

const IDENTITY: Jacobian = { x: 1n, y: 1n, z: 0n };

/** dbl-2009-l (a = 0). */
function jDouble(F: Field, p: Jacobian): Jacobian {
  if (p.z === 0n) return p;
  const a = F.square(p.x);
  const b = F.square(p.y);
  const c = F.square(b);
  let d = F.sub(F.sub(F.square(F.add(p.x, b)), a), c);
  d = F.add(d, d);
  const e = F.add(F.add(a, a), a);
  const f = F.square(e);
  const x3 = F.sub(f, F.add(d, d));
  let c8 = F.add(c, c);
  c8 = F.add(c8, c8);
  c8 = F.add(c8, c8);
  const y3 = F.sub(F.mul(e, F.sub(d, x3)), c8);
  const yz = F.mul(p.y, p.z);
  return { x: x3, y: y3, z: F.add(yz, yz) };
}

/** madd-2007-bl: Jacobian plus affine. */
function jAddAffine(F: Field, p: Jacobian, qx: bigint, qy: bigint): Jacobian {
  if (p.z === 0n) return { x: qx, y: qy, z: 1n };
  const z1z1 = F.square(p.z);
  const u2 = F.mul(qx, z1z1);
  const s2 = F.mul(F.mul(qy, p.z), z1z1);
  const h = F.sub(u2, p.x);
  let r = F.sub(s2, p.y);
  if (h === 0n) return r === 0n ? jDouble(F, p) : IDENTITY;
  const hh = F.square(h);
  let i = F.add(hh, hh);
  i = F.add(i, i);
  const j = F.mul(h, i);
  r = F.add(r, r);
  const v = F.mul(p.x, i);
  const x3 = F.sub(F.sub(F.square(r), j), F.add(v, v));
  const yj = F.mul(p.y, j);
  const y3 = F.sub(F.mul(r, F.sub(v, x3)), F.add(yj, yj));
  const z3 = F.sub(F.sub(F.square(F.add(p.z, h)), z1z1), hh);
  return { x: x3, y: y3, z: z3 };
}

/** add-2007-bl. */
function jAdd(F: Field, p: Jacobian, q: Jacobian): Jacobian {
  if (p.z === 0n) return q;
  if (q.z === 0n) return p;
  const z1z1 = F.square(p.z);
  const z2z2 = F.square(q.z);
  const u1 = F.mul(p.x, z2z2);
  const u2 = F.mul(q.x, z1z1);
  const s1 = F.mul(F.mul(p.y, q.z), z2z2);
  const s2 = F.mul(F.mul(q.y, p.z), z1z1);
  const h = F.sub(u2, u1);
  let r = F.sub(s2, s1);
  if (h === 0n) return r === 0n ? jDouble(F, p) : IDENTITY;
  const h2 = F.add(h, h);
  const i = F.square(h2);
  const j = F.mul(h, i);
  r = F.add(r, r);
  const v = F.mul(u1, i);
  const x3 = F.sub(F.sub(F.square(r), j), F.add(v, v));
  const sj = F.mul(s1, j);
  const y3 = F.sub(F.mul(r, F.sub(v, x3)), F.add(sj, sj));
  const z3 = F.mul(F.sub(F.sub(F.square(F.add(p.z, q.z)), z1z1), z2z2), h);
  return { x: x3, y: y3, z: z3 };
}

function toAffine(F: Field, p: Jacobian): Affine | null {
  if (p.z === 0n) return null;
  const zi = F.inv(p.z);
  const zi2 = F.square(zi);
  return { x: F.mul(p.x, zi2), y: F.mul(p.y, F.mul(zi2, zi)) };
}

/** Window width minimising bucket additions plus window sums for `n` points. */
function windowBits(n: number, bits: number): number {
  let best = 1;
  let bestCost = Infinity;
  for (let c = 1; c <= 16; c++) {
    const windows = Math.ceil((bits + 1) / c);
    // batched affine add ≈ 6 mul, Jacobian mixed + full add ≈ 27 mul
    const cost = windows * (6 * n + 27 * (1 << (c - 1)));
    if (cost < bestCost) {
      bestCost = cost;
      best = c;
    }
  }
  return best;
}

/**
 * Σ sᵢ·Pᵢ for scalars in [0, order) of at most `bits` bits. Signed digits
 * of width c put each point in one of 2^(c-1) buckets per window, so c·W
 * must cover bits + 1 for the last carry.
 */
export function msm(
  F: Field,
  order: bigint,
  bits: number,
  scalars: bigint[],
  points: Affine[],
): Affine | null {
  const len = Math.min(scalars.length, points.length);
  let live = 0;
  for (let i = 0; i < len; i++) if (scalars[i] % order !== 0n) live++;
  if (live === 0) return null;
  const c = windowBits(live, bits);
  const windows = Math.ceil((bits + 1) / c);
  const half = 1 << (c - 1);
  const full = 1 << c;
  const mask = BigInt(full - 1);
  const shift = BigInt(c);

  // One bucket addition per (point, window) with a non-zero digit.
  let itemB = new Int32Array(live * windows);
  let itemP = new Int32Array(live * windows);
  let count = 0;
  const negY = new Array<bigint>(len);
  for (let i = 0; i < len; i++) {
    let v = scalars[i];
    if (v < 0n || v >= order) v = ((v % order) + order) % order;
    if (v === 0n) continue;
    let carry = 0;
    for (let w = 0; w < windows; w++) {
      let d = Number(v & mask) + carry;
      v >>= shift;
      carry = 0;
      if (d > half) {
        d -= full;
        carry = 1;
      }
      if (d === 0) continue;
      if (d < 0) {
        if (negY[i] === undefined) negY[i] = F.neg(points[i].y);
        itemB[count] = w * half - d - 1;
        itemP[count] = i * 2 + 1;
      } else {
        itemB[count] = w * half + d - 1;
        itemP[count] = i * 2;
      }
      count++;
    }
  }

  // Fill the buckets in passes, each pass one batch. A bucket takes one
  // addition per pass; further points bound for it in the same pass are
  // added to each other in pairs, the sums going on to the next pass, so a
  // bucket loaded with L points needs about log2(L) passes (small scalars
  // put every point of a column in the same few buckets).
  // Slots [0, nb) are the buckets, the rest hold pair sums; an item is a
  // bucket and a source, `p >= 0` an input point (2i + negated) and
  // `p < 0` the pair-sum slot −p − 1.
  const nb = windows * half;
  const cap = nb + count;
  const slots: Points = {
    x: new Array<bigint>(cap).fill(0n),
    y: new Array<bigint>(cap).fill(0n),
    inf: new Uint8Array(cap).fill(1),
  };
  let free = nb;
  const sx = (p: number) => (p >= 0 ? points[p >> 1].x : slots.x[-p - 1]);
  const sy = (p: number) =>
    p >= 0 ? (p & 1 ? negY[p >> 1] : points[p >> 1].y) : slots.y[-p - 1];
  const scheduled = new Int32Array(nb);
  const pendingAt = new Int32Array(nb);
  const pendingItem = new Int32Array(nb);
  // one entry per pending event, and a bucket can pend several times a pass
  const pendingBuckets = new Int32Array(count);
  let nextB = new Int32Array(count);
  let nextP = new Int32Array(count);
  const targets = new Int32Array(count);
  const qx = new Array<bigint>(count);
  const qy = new Array<bigint>(count);
  for (let pass = 1; count > 0; pass++) {
    let m = 0;
    let rest = 0;
    let np = 0;
    for (let j = 0; j < count; j++) {
      const b = itemB[j];
      const p = itemP[j];
      if (p < 0 && slots.inf[-p - 1]) continue; // a pair that cancelled
      if (scheduled[b] !== pass) {
        if (slots.inf[b]) {
          slots.x[b] = sx(p);
          slots.y[b] = sy(p);
          slots.inf[b] = 0;
          continue;
        }
        scheduled[b] = pass;
        targets[m] = b;
        qx[m] = sx(p);
        qy[m] = sy(p);
        m++;
      } else if (pendingAt[b] !== pass) {
        pendingAt[b] = pass;
        pendingItem[b] = p;
        pendingBuckets[np++] = b;
      } else {
        const s = free++;
        const a = pendingItem[b];
        slots.x[s] = sx(a);
        slots.y[s] = sy(a);
        slots.inf[s] = 0;
        targets[m] = s;
        qx[m] = sx(p);
        qy[m] = sy(p);
        m++;
        nextB[rest] = b;
        nextP[rest] = -s - 1;
        rest++;
        pendingAt[b] = 0;
      }
    }
    for (let j = 0; j < np; j++) {
      const b = pendingBuckets[j];
      // a bucket can be listed twice (pended, paired, pended again)
      if (pendingAt[b] !== pass) continue;
      pendingAt[b] = 0;
      nextB[rest] = b;
      nextP[rest] = pendingItem[b];
      rest++;
    }
    batchAffine(F, slots, targets, m, qx, qy);
    [itemB, nextB] = [nextB, itemB];
    [itemP, nextP] = [nextP, itemP];
    count = rest;
  }
  const buckets = slots;

  // Window sums Σ j·B_j by running sums, then Horner over the windows.
  let acc = IDENTITY;
  for (let w = windows - 1; w >= 0; w--) {
    for (let s = 0; s < c; s++) acc = jDouble(F, acc);
    let running = IDENTITY;
    let total = IDENTITY;
    for (let j = half - 1; j >= 0; j--) {
      const b = w * half + j;
      if (!buckets.inf[b])
        running = jAddAffine(F, running, buckets.x[b], buckets.y[b]);
      if (running.z !== 0n) total = jAdd(F, total, running);
    }
    acc = jAdd(F, acc, total);
  }
  return toAffine(F, acc);
}

/**
 * `sᵢ·Pᵢ` for every i, all points stepping through one width-4 NAF schedule
 * together so each doubling round and each addition round is one batch.
 * `scalars` may be a single scalar shared by every point.
 */
export function mulEach(
  F: Field,
  order: bigint,
  scalars: bigint | bigint[],
  points: (Affine | null)[],
): (Affine | null)[] {
  const n = points.length;
  const scalarOf = (i: number) => {
    let v = typeof scalars === "bigint" ? scalars : scalars[i];
    if (v < 0n || v >= order) v = ((v % order) + order) % order;
    return v;
  };
  // Width-4 NAF digits, least significant first: odd digits in ±{1,3,5,7}.
  const naf: Int8Array[] = [];
  let top = 0;
  const shared = typeof scalars === "bigint";
  for (let i = 0; i < n; i++) {
    if (shared && i > 0) {
      naf.push(naf[0]);
      continue;
    }
    let v = scalarOf(i);
    const digits: number[] = [];
    while (v > 0n) {
      let d = 0;
      if (v & 1n) {
        d = Number(v & 15n);
        if (d >= 8) d -= 16;
        v -= BigInt(d);
      }
      digits.push(d);
      v >>= 1n;
    }
    naf.push(Int8Array.from(digits));
    top = Math.max(top, digits.length);
  }
  if (shared) top = naf.length ? naf[0].length : 0;

  // Odd multiples P, 3P, 5P, 7P per point: tables[m] holds (2m+1)·P.
  const idx = Int32Array.from({ length: n }, (_, i) => i);
  const base: Points = {
    x: points.map((p) => (p ? p.x : 0n)),
    y: points.map((p) => (p ? p.y : 0n)),
    inf: Uint8Array.from(points, (p) => (p ? 0 : 1)),
  };
  const twice: Points = {
    x: base.x.slice(),
    y: base.y.slice(),
    inf: base.inf.slice(),
  };
  batchAffine(F, twice, idx, n, null, null);
  const tables: Points[] = [base];
  for (let m = 1; m < 4; m++) {
    const prev = tables[m - 1];
    const next: Points = {
      x: prev.x.slice(),
      y: prev.y.slice(),
      inf: prev.inf.slice(),
    };
    const live: number[] = [];
    const ax: bigint[] = [];
    const ay: bigint[] = [];
    for (let i = 0; i < n; i++)
      if (!twice.inf[i]) {
        live.push(i);
        ax.push(twice.x[i]);
        ay.push(twice.y[i]);
      }
    batchAffine(F, next, live, live.length, ax, ay);
    tables.push(next);
  }

  const r: Points = {
    x: new Array<bigint>(n).fill(0n),
    y: new Array<bigint>(n).fill(0n),
    inf: new Uint8Array(n).fill(1),
  };
  const t = new Int32Array(n);
  const qx = new Array<bigint>(n);
  const qy = new Array<bigint>(n);
  for (let pos = top - 1; pos >= 0; pos--) {
    batchAffine(F, r, idx, n, null, null);
    let m = 0;
    for (let i = 0; i < n; i++) {
      const d = pos < naf[i].length ? naf[i][pos] : 0;
      if (d === 0) continue;
      const tb = tables[(Math.abs(d) - 1) >> 1];
      if (tb.inf[i]) continue;
      t[m] = i;
      qx[m] = tb.x[i];
      qy[m] = d > 0 ? tb.y[i] : F.neg(tb.y[i]);
      m++;
    }
    batchAffine(F, r, t, m, qx, qy);
  }
  return Array.from({ length: n }, (_, i) =>
    r.inf[i] ? null : { x: r.x[i], y: r.y[i] },
  );
}

/** `Pᵢ + Qᵢ` for every i in one batch. */
export function addEach(
  F: Field,
  ps: (Affine | null)[],
  qs: (Affine | null)[],
): (Affine | null)[] {
  const n = ps.length;
  const r: Points = {
    x: ps.map((p) => (p ? p.x : 0n)),
    y: ps.map((p) => (p ? p.y : 0n)),
    inf: Uint8Array.from(ps, (p) => (p ? 0 : 1)),
  };
  const t: number[] = [];
  const qx: bigint[] = [];
  const qy: bigint[] = [];
  for (let i = 0; i < n; i++) {
    const q = qs[i];
    if (!q) continue;
    t.push(i);
    qx.push(q.x);
    qy.push(q.y);
  }
  batchAffine(F, r, t, t.length, qx, qy);
  return Array.from({ length: n }, (_, i) =>
    r.inf[i] ? null : { x: r.x[i], y: r.y[i] },
  );
}
