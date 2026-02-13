/**
 * Abstract interface for elliptic curve group operations.
 *
 * Each OPAQUE cipher suite binds to a specific group.
 * This interface normalizes the API across all supported curves.
 */

/** Opaque wrapper for a curve point (internal representation varies by curve). */
export interface GroupElement {
  /** Curve-specific internal point object. */
  readonly _point: unknown;
}

/** Group operations for a specific elliptic curve. */
export interface GroupOps {
  /** Size of a scalar in bytes. */
  readonly scalarSize: number;
  /** Size of a compressed group element in bytes. */
  readonly elementSize: number;

  /** Hash arbitrary input to a group element (RFC 9380 hash_to_curve). */
  hashToGroup(input: Uint8Array, dst: Uint8Array): GroupElement;

  /** Generate a uniform random scalar. */
  randomScalar(): Uint8Array;

  /** Scalar multiplication: scalar * element. */
  scalarMult(scalar: Uint8Array, element: GroupElement): GroupElement;

  /** Compute the multiplicative inverse of a scalar in the group order field. */
  scalarInverse(scalar: Uint8Array): Uint8Array;

  /** Serialize a group element to bytes (compressed). */
  serializeElement(element: GroupElement): Uint8Array;

  /** Deserialize bytes to a group element. Throws on invalid input. */
  deserializeElement(bytes: Uint8Array): GroupElement;

  /** Generate a fresh keypair: { secretKey, publicKey }. */
  generateKeypair(): { secretKey: Uint8Array; publicKey: Uint8Array };

  /** Compute ECDH shared secret: secretKey * publicKeyPoint → x-coordinate bytes. */
  ecdh(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;

  /** The identity (zero) element. */
  identity(): GroupElement;

  /** Add two group elements. */
  add(a: GroupElement, b: GroupElement): GroupElement;

  /** Scalar multiplication by the generator: scalar * G. */
  scalarBaseMult(scalar: Uint8Array): GroupElement;

  /** Reduce arbitrary bytes to a valid non-zero scalar (mod group order). */
  scalarReduce(bytes: Uint8Array): Uint8Array;
}
