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
export const FP_MODULUS = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n;

/** Pallas scalar field modulus (= Vesta base). */
export const FQ_MODULUS = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001n;

/** A prime field GF(p) over BigInt. Immutable elements are plain reduced BigInts. */
export class Field {
  readonly p: bigint;

  constructor(modulus: bigint) {
    this.p = modulus;
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
    return (a * b) % this.p;
  }

  square(a: bigint): bigint {
    return (a * a) % this.p;
  }

  /** Modular exponentiation (square-and-multiply). */
  pow(a: bigint, e: bigint): bigint {
    let base = a % this.p;
    if (base < 0n) base += this.p;
    let result = 1n;
    let exp = e;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % this.p;
      base = (base * base) % this.p;
      exp >>= 1n;
    }
    return result;
  }

  /** Multiplicative inverse via Fermat's little theorem: a^(p-2) mod p. */
  inv(a: bigint): bigint {
    if (a % this.p === 0n) throw new Error('Field.inv: zero has no inverse');
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
    if (b.length !== 32) throw new Error('Field.fromBytes: expected 32 bytes');
    let v = 0n;
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    if (v >= this.p) throw new Error('Field.fromBytes: non-canonical (>= modulus)');
    return v;
  }

  /**
   * Reduce 64 wide little-endian bytes into the field (pasta_curves
   * `FromUniformBytes<64>`): interpret as a 512-bit LE integer, reduce mod p.
   */
  fromUniformBytes(b: Uint8Array): bigint {
    if (b.length !== 64) throw new Error('Field.fromUniformBytes: expected 64 bytes');
    let v = 0n;
    for (let i = 63; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    return this.mod(v);
  }
}

/** Pallas base field (Fp). */
export const Fp = new Field(FP_MODULUS);
/** Pallas scalar field (Fq). */
export const Fq = new Field(FQ_MODULUS);
