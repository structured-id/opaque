/**
 * Pasta prime-field arithmetic (pure TS, BigInt) — foundation for the in-TS ZKPP
 * prover (no-WASM fallback). Byte-for-byte field model of `pasta_curves`:
 *   - Fp = Pallas base field   = Vesta scalar field
 *   - Fq = Pallas scalar field = Vesta base field
 *
 * Canonical 32-byte encoding is little-endian (matches `pasta_curves` PrimeField::to_repr).
 *
 * NOTE: BigInt modular arithmetic is correct but ~100-1000x slower than native;
 * this exists so a no-WASM client can prove at all, not quickly. Montgomery / WASM
 * remains the fast path.
 */

/** Pallas base field modulus (= Vesta scalar). */
export const FP_MODULUS =
  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n;

/** Pallas scalar field modulus (= Vesta base). */
export const FQ_MODULUS =
  0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001n;

/** A prime field GF(p) over BigInt. Immutable elements are plain reduced BigInts. */
export class Field {
  readonly p: bigint;
  // Barrett constant mu = floor(2^512 / p). Both Pasta primes are < 2^255, so a
  // product of two reduced elements is < 2^510 < 2^512 and Barrett reduction
  // (2 muls + shift, no bignum division) can replace the costly `% p`.
  private readonly mu: bigint;
  // Non-negative product reducer into [0, p). Whether Barrett beats native `% p`
  // is microarchitecture-dependent (Barrett wins on fast cores where bignum
  // division is expensive relative to mul, e.g. x86 / Apple Silicon; native `% p`
  // wins on weak cores e.g. Cortex-A72), so the strategy is auto-picked once at
  // construction. Both paths produce identical values, so this never affects the
  // proof bytes — only speed.
  private readonly red: (t: bigint) => bigint;

  constructor(modulus: bigint) {
    this.p = modulus;
    this.mu = (1n << 512n) / modulus;
    const p = modulus;
    const mu = this.mu;
    // q = floor(t*mu / 2^512) <= floor(t/p) so r = t - q*p >= 0; a couple of
    // conditional subs bring it below p.
    const barrett = (t: bigint): bigint => {
      let r = t - ((t * mu) >> 512n) * p;
      while (r >= p) r -= p;
      return r;
    };
    const native = (t: bigint): bigint => t % p; // t >= 0, so result in [0, p)
    this.red = Field.barrettFaster(p, mu, barrett, native) ? barrett : native;
  }

  /** Time both reducers on a sample workload; true if Barrett is faster here. */
  private static barrettFaster(
    p: bigint,
    mu: bigint,
    barrett: (t: bigint) => bigint,
    native: (t: bigint) => bigint,
  ): boolean {
    const a =
      0x1a2b3c4d5e6f7890abcdef0123456789fedcba9876543210aabbccddeeff0011n % p;
    const b =
      0x0fedcba987654321001122334455667788990011223344556677889900aabbn % p;
    const WARM = 2000;
    const ITER = 8000;
    let s = a;
    for (let i = 0; i < WARM; i++) s = native(s * b);
    for (let i = 0; i < WARM; i++) s = barrett(s * b);
    let t0 = performance.now();
    s = a;
    for (let i = 0; i < ITER; i++) s = native(s * b);
    const tNative = performance.now() - t0;
    t0 = performance.now();
    s = a;
    for (let i = 0; i < ITER; i++) s = barrett(s * b);
    const tBarrett = performance.now() - t0;
    return tBarrett < tNative;
  }

  /** Reduce any integer into [0, p). */
  mod(a: bigint): bigint {
    const r = a % this.p;
    return r < 0n ? r + this.p : r;
  }

  add(a: bigint, b: bigint): bigint {
    const r = a + b;
    return r >= this.p ? r - this.p : r;
  }

  sub(a: bigint, b: bigint): bigint {
    const r = a - b;
    return r < 0n ? r + this.p : r;
  }

  neg(a: bigint): bigint {
    return a === 0n ? 0n : this.p - a;
  }

  mul(a: bigint, b: bigint): bigint {
    return this.red(a * b);
  }

  square(a: bigint): bigint {
    return this.red(a * a);
  }

  /** Modular exponentiation (square-and-multiply). */
  pow(a: bigint, e: bigint): bigint {
    let base = a % this.p;
    if (base < 0n) base += this.p;
    let result = 1n;
    let exp = e;
    while (exp > 0n) {
      if (exp & 1n) result = this.red(result * base);
      base = this.red(base * base);
      exp >>= 1n;
    }
    return result;
  }

  /** Multiplicative inverse via Fermat's little theorem: a^(p-2) mod p. */
  inv(a: bigint): bigint {
    if (a % this.p === 0n) throw new Error("Field.inv: zero has no inverse");
    return this.pow(a, this.p - 2n);
  }

  /** 32-byte little-endian canonical encoding (pasta_curves to_repr). */
  toBytes(a: bigint): Uint8Array {
    const out = new Uint8Array(32);
    let v = this.mod(a);
    for (let i = 0; i < 32; i++) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }

  /** Decode a 32-byte little-endian canonical element; throws if >= p (non-canonical). */
  fromBytes(b: Uint8Array): bigint {
    if (b.length !== 32) throw new Error("Field.fromBytes: expected 32 bytes");
    let v = 0n;
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    if (v >= this.p)
      throw new Error("Field.fromBytes: non-canonical (>= modulus)");
    return v;
  }

  /**
   * Reduce 64 wide little-endian bytes into the field (pasta_curves
   * `FromUniformBytes<64>`): interpret as a 512-bit LE integer, reduce mod p.
   */
  fromUniformBytes(b: Uint8Array): bigint {
    if (b.length !== 64)
      throw new Error("Field.fromUniformBytes: expected 64 bytes");
    let v = 0n;
    for (let i = 63; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    return this.mod(v);
  }
}

/** Pallas base field (Fp). */
export const Fp = new Field(FP_MODULUS);
/** Pallas scalar field (Fq). */
export const Fq = new Field(FQ_MODULUS);
