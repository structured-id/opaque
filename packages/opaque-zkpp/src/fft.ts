/**
 * Radix-2 NTT over the Pallas base field — byte-identical to halo2's
 * `arithmetic::best_fft` (serial path): bit-reversal permutation then in-place
 * decimation-in-time butterflies. Forward transform = coefficients → evaluations
 * at powers of `omega`.
 *
 * Fp is 2-adic with S = 32, so domains up to 2^32 have a primitive root of unity
 * `omega = ROOT_OF_UNITY^(2^(S − log_n))`.
 */
import { Fp } from './field.js';

/** Pasta Fp 2-adicity. */
export const FP_S = 32;

const leHex = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};

/** 2^S-th primitive root of unity in Fp (pasta_curves Fp::ROOT_OF_UNITY). */
export const FP_ROOT_OF_UNITY = leHex(
  '2fa37ed8ab6fadbd8475bbb7f22b32ea1af8610583202136daeb30acde74ce2b',
);

/** Primitive 2^logN-th root of unity for a domain of size 2^logN. */
export function omegaForSize(logN: number): bigint {
  return Fp.pow(FP_ROOT_OF_UNITY, 1n << BigInt(FP_S - logN));
}

function bitreverse(k: number, bits: number): number {
  let r = 0;
  for (let i = 0; i < bits; i++) {
    r = (r << 1) | (k & 1);
    k >>= 1;
  }
  return r;
}

/** In-place forward NTT (matches halo2 serial best_fft). `a.length === 2^logN`. */
export function bestFft(a: bigint[], omega: bigint, logN: number): void {
  const n = a.length;
  for (let k = 0; k < n; k++) {
    const rk = bitreverse(k, logN);
    if (k < rk) {
      const t = a[rk];
      a[rk] = a[k];
      a[k] = t;
    }
  }
  let m = 1;
  for (let stage = 0; stage < logN; stage++) {
    const wm = Fp.pow(omega, BigInt(n / (2 * m)));
    let k = 0;
    while (k < n) {
      let w = 1n;
      for (let j = 0; j < m; j++) {
        const t = Fp.mul(a[k + j + m], w);
        a[k + j + m] = Fp.sub(a[k + j], t);
        a[k + j] = Fp.add(a[k + j], t);
        w = Fp.mul(w, wm);
      }
      k += 2 * m;
    }
    m *= 2;
  }
}
