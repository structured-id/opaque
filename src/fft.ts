/**
 * Radix-2 NTT over the Pallas base field — byte-identical to halo2's
 * `arithmetic::best_fft` (serial path): bit-reversal permutation then in-place
 * decimation-in-time butterflies. Forward transform = coefficients → evaluations
 * at powers of `omega`.
 *
 * Fp is 2-adic with S = 32, so domains up to 2^32 have a primitive root of unity
 * `omega = ROOT_OF_UNITY^(2^(S − log_n))`.
 */
import { Fp } from "./field.js";

/** Pasta Fp 2-adicity. */
export const FP_S = 32;

const leHex = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2)
    v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};

/** 2^S-th primitive root of unity in Fp (pasta_curves Fp::ROOT_OF_UNITY). */
export const FP_ROOT_OF_UNITY = leHex(
  "2fa37ed8ab6fadbd8475bbb7f22b32ea1af8610583202136daeb30acde74ce2b",
);

/** Primitive 2^logN-th root of unity for a domain of size 2^logN. */
export function omegaForSize(logN: number): bigint {
  return Fp.pow(FP_ROOT_OF_UNITY, 1n << BigInt(FP_S - logN));
}

/** omega^j for j < 2^(logN-1), per (omega, logN); a stage of span m reads every n/(2m)-th. */
const twiddleCache = new Map<string, bigint[]>();
function twiddles(omega: bigint, logN: number): bigint[] {
  const key = `${logN}:${omega}`;
  let tw = twiddleCache.get(key);
  if (!tw) {
    const half = 1 << (logN - 1);
    tw = new Array<bigint>(half);
    let w = 1n;
    for (let j = 0; j < half; j++) {
      tw[j] = w;
      w = Fp.mul(w, omega);
    }
    twiddleCache.set(key, tw);
  }
  return tw;
}

function bitreverse(k: number, bits: number): number {
  let r = 0;
  for (let i = 0; i < bits; i++) {
    r = (r << 1) | (k & 1);
    k >>= 1;
  }
  return r;
}

/**
 * In-place forward NTT (matches halo2 serial best_fft). `a.length === 2^logN`.
 * When only the first `nonzero` inputs can be non-zero (a zero-padded
 * polynomial, `nonzero` a power of two), the first log(n/nonzero) stages only
 * copy each value across its block and are done as copies.
 */
export function bestFft(
  a: bigint[],
  omega: bigint,
  logN: number,
  nonzero = a.length,
): void {
  const n = a.length;
  if (n === 1) return;
  for (let k = 0; k < n; k++) {
    const rk = bitreverse(k, logN);
    if (k < rk) {
      const t = a[rk];
      a[rk] = a[k];
      a[k] = t;
    }
  }
  let m = 1;
  let stage = 0;
  // Bit reversal puts input i < nonzero at a multiple of n/nonzero; the
  // butterflies of the first stages then see a zero partner and duplicate.
  const block = nonzero < n ? n / nonzero : 1;
  if (block > 1) {
    for (let k = 0; k < n; k += block) {
      const v = a[k];
      for (let j = 1; j < block; j++) a[k + j] = v;
    }
    while (m < block) {
      m *= 2;
      stage++;
    }
  }
  const tw = twiddles(omega, logN);
  for (; stage < logN; stage++) {
    const step = n / (2 * m);
    for (let k = 0; k < n; k += 2 * m) {
      // j = 0: the twiddle is 1
      const t0 = a[k + m];
      const u0 = a[k];
      a[k + m] = Fp.sub(u0, t0);
      a[k] = Fp.add(u0, t0);
      for (let j = 1; j < m; j++) {
        const t = Fp.mul(a[k + j + m], tw[j * step]);
        const u = a[k + j];
        a[k + j + m] = Fp.sub(u, t);
        a[k + j] = Fp.add(u, t);
      }
    }
    m *= 2;
  }
}
