/**
 * OPAQUE cipher suite definitions (RFC 9807).
 *
 * Supports RFC 9807 standard suites and SID extended suites.
 * Each suite binds: elliptic curve group + hash + KDF + MAC.
 */

/**
 * Curve identifier matching proto `CurveId` enum
 * (see arch/security/crypto-curve-agility.md).
 */
export enum CurveId {
  RISTRETTO255 = 1,
  P256 = 2,
  P384 = 3,
  P521 = 4,
}

/** Hash algorithm for the suite. */
export type HashId = 'SHA-256' | 'SHA-384' | 'SHA-512';

/** Cipher suite identifier (wire protocol discriminator). */
export enum CipherSuiteId {
  /** RFC 9807 primary: ristretto255 + SHA-512 */
  RISTRETTO255_SHA512 = 0x0001,
  /** RFC 9807 alternative: P-256 + SHA-256 */
  P256_SHA256 = 0x0002,
  /** SID extended: P-384 + SHA-384 (CNSA 1.0) */
  P384_SHA384 = 0x1003,
  /** SID extended: P-521 + SHA-512 (CNSA 2.0) */
  P521_SHA512 = 0x1004,
}

/** Full cipher suite configuration. */
export interface CipherSuite {
  readonly id: CipherSuiteId;
  readonly name: string;
  readonly curve: CurveId;
  readonly hash: HashId;
  /** OPRF output size in bytes. */
  readonly oprfOutputSize: number;
  /** Scalar size in bytes. */
  readonly scalarSize: number;
  /** Compressed group element size in bytes. */
  readonly elementSize: number;
  /** Nonce size for AKE (bytes). */
  readonly nonceSize: number;
  /** MAC output size in bytes. */
  readonly macSize: number;
  /** Key size for envelope encryption (bytes). */
  readonly keySize: number;
  /** Whether this is an RFC 9807 standard suite. */
  readonly isStandard: boolean;
}

// ── Predefined suites ──

export const RISTRETTO255_SHA512: CipherSuite = {
  id: CipherSuiteId.RISTRETTO255_SHA512,
  name: 'OPAQUE-Ristretto255-SHA512',
  curve: CurveId.RISTRETTO255,
  hash: 'SHA-512',
  oprfOutputSize: 64,
  scalarSize: 32,
  elementSize: 32,
  nonceSize: 32,
  macSize: 64,
  keySize: 32,
  isStandard: true,
};

export const P256_SHA256: CipherSuite = {
  id: CipherSuiteId.P256_SHA256,
  name: 'OPAQUE-P256-SHA256',
  curve: CurveId.P256,
  hash: 'SHA-256',
  oprfOutputSize: 32,
  scalarSize: 32,
  elementSize: 33,
  nonceSize: 32,
  macSize: 32,
  keySize: 32,
  isStandard: true,
};

export const P384_SHA384: CipherSuite = {
  id: CipherSuiteId.P384_SHA384,
  name: 'SID-P384-SHA384',
  curve: CurveId.P384,
  hash: 'SHA-384',
  oprfOutputSize: 48,
  scalarSize: 48,
  elementSize: 49,
  nonceSize: 32,
  macSize: 48,
  keySize: 32,
  isStandard: false,
};

export const P521_SHA512: CipherSuite = {
  id: CipherSuiteId.P521_SHA512,
  name: 'SID-P521-SHA512',
  curve: CurveId.P521,
  hash: 'SHA-512',
  oprfOutputSize: 64,
  scalarSize: 66,
  elementSize: 67,
  nonceSize: 32,
  macSize: 64,
  keySize: 32,
  isStandard: false,
};

/** All supported cipher suites. */
export const SUITES: ReadonlyMap<CipherSuiteId, CipherSuite> = new Map([
  [CipherSuiteId.RISTRETTO255_SHA512, RISTRETTO255_SHA512],
  [CipherSuiteId.P256_SHA256, P256_SHA256],
  [CipherSuiteId.P384_SHA384, P384_SHA384],
  [CipherSuiteId.P521_SHA512, P521_SHA512],
]);

/** Default suite (RFC 9807 standard = Ristretto255). */
export const DEFAULT_SUITE = CipherSuiteId.RISTRETTO255_SHA512;

/** Get suite by ID, throws if unknown. */
export function getSuite(id: CipherSuiteId): CipherSuite {
  const suite = SUITES.get(id);
  if (!suite) throw new Error(`Unknown cipher suite: 0x${id.toString(16)}`);
  return suite;
}

/** Get suite by CurveId. */
export function getSuiteByCurve(curve: CurveId): CipherSuite {
  for (const suite of SUITES.values()) {
    if (suite.curve === curve) return suite;
  }
  throw new Error(`No suite for curve: ${curve}`);
}
