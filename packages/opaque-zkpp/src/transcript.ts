/**
 * Fiat-Shamir transcript — byte-identical to halo2 `Blake2bWrite`/`Blake2bRead`
 * over Vesta (the IPA commitment curve). BLAKE2b, 64-byte output, personalization
 * "Halo2-Transcript". Domain-prefix bytes: challenge=0, point=1, scalar=2.
 *
 *   common_point:  [1] ‖ x.to_repr ‖ y.to_repr     (x,y ∈ Fq, the Vesta base field)
 *   common_scalar: [2] ‖ s.to_repr                 (s   ∈ Fp, the Vesta scalar field)
 *   squeeze:       absorb [0]; challenge = Fp.from_uniform_bytes(clone.finalize())
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { Fp, Fq } from './field.js';
import type { Point } from './curve.js';

const PERSONAL = new TextEncoder().encode('Halo2-Transcript');
const PREFIX_CHALLENGE = 0;
const PREFIX_POINT = 1;
const PREFIX_SCALAR = 2;

export class Transcript {
  private state = blake2b.create({ dkLen: 64, personalization: PERSONAL });

  /** Absorb a Vesta point (its affine x, y over Fq). Point-at-infinity is invalid. */
  commonPoint(p: NonNullable<Point>): void {
    this.state.update(Uint8Array.of(PREFIX_POINT));
    this.state.update(Fq.toBytes(p.x));
    this.state.update(Fq.toBytes(p.y));
  }

  /** Absorb a scalar (Vesta scalar field Fp). */
  commonScalar(s: bigint): void {
    this.state.update(Uint8Array.of(PREFIX_SCALAR));
    this.state.update(Fp.toBytes(s));
  }

  /** Squeeze a challenge scalar in Fp (absorbs the challenge prefix into the state). */
  squeezeChallenge(): bigint {
    this.state.update(Uint8Array.of(PREFIX_CHALLENGE));
    return Fp.fromUniformBytes(this.state.clone().digest());
  }
}
