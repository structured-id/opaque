/**
 * The randomness a client operation draws, as a byte source. Every draw goes
 * through it in the order the Rust reference consumes its RNG, so a recorded
 * stream replays a Rust run byte for byte in the cross-check vectors.
 */
export type RandomSource = (length: number) => Uint8Array;

/** Cryptographically secure bytes from WebCrypto. */
export const secureRandom: RandomSource = (length) =>
  crypto.getRandomValues(new Uint8Array(length));
