/**
 * IPA polynomial commitment (halo2 inner-product-argument scheme over Vesta).
 *   commit(poly, r) = Σ poly[i]·g[i] + r·w
 * where g[] are the coefficient-basis generators and w the blinding generator
 * (both derived in-circuit-free via hash_to_curve("Halo2-Parameters"); shipped to
 * the no-WASM client). Byte-identical to halo2 `Params::commit`.
 */
import { Vesta, type Point } from './curve.js';

export interface IpaParams {
  /** Coefficient-basis generators g[0..n). */
  g: { x: bigint; y: bigint }[];
  /** Blinding generator w. */
  w: { x: bigint; y: bigint };
}

/** Pedersen/IPA commitment to a coefficient-form polynomial with blinding `r`. */
export function ipaCommit(params: IpaParams, coeffs: bigint[], blind: bigint): Point {
  if (coeffs.length > params.g.length) {
    throw new Error('ipaCommit: more coefficients than generators');
  }
  const base = Vesta.msm(coeffs, params.g.slice(0, coeffs.length));
  const blinded = Vesta.scalarMul(blind, params.w);
  return Vesta.add(base, blinded);
}
