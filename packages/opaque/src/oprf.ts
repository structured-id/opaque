/**
 * OPRF operations (RFC 9497).
 *
 * Uses @noble/curves built-in OPRF for RFC 9807 standard suites:
 * ristretto255, P-256, P-384, P-521.
 *
 * OPAQUE uses base mode OPRF (not VOPRF or POPRF).
 */
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { p256_oprf, p384_oprf, p521_oprf } from '@noble/curves/nist.js';
import { CurveId } from './suites.js';

/** OPRF blind result: blind scalar + blinded element to send to server. */
export interface OprfBlindResult {
  blind: Uint8Array;
  blindedElement: Uint8Array;
}

/** OPRF key pair for server-side evaluation. */
export interface OprfKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

interface OprfSuite {
  generateKeyPair(): OprfKeyPair;
  blind(input: Uint8Array): { blind: Uint8Array; blinded: Uint8Array };
  blindEvaluate(secretKey: Uint8Array, blinded: Uint8Array): Uint8Array;
  finalize(input: Uint8Array, blind: Uint8Array, evaluated: Uint8Array): Uint8Array;
  evaluate(secretKey: Uint8Array, input: Uint8Array): Uint8Array;
}

function getBuiltinOprf(curve: CurveId): OprfSuite | null {
  switch (curve) {
    case CurveId.RISTRETTO255:
      return ristretto255_oprf.oprf as unknown as OprfSuite;
    case CurveId.P256:
      return p256_oprf.oprf as unknown as OprfSuite;
    case CurveId.P384:
      return p384_oprf.oprf as unknown as OprfSuite;
    case CurveId.P521:
      return p521_oprf.oprf as unknown as OprfSuite;
    default:
      return null;
  }
}

// ── Public API ──

function getOprfSuite(curve: CurveId): OprfSuite {
  const builtin = getBuiltinOprf(curve);
  if (builtin) return builtin;
  throw new Error(`Unsupported curve for OPRF: ${curve}`);
}

/** Generate OPRF server key pair. */
export function oprfGenerateKeyPair(curve: CurveId): OprfKeyPair {
  return getOprfSuite(curve).generateKeyPair();
}

/** Client: blind input for OPRF evaluation. */
export function oprfBlind(curve: CurveId, input: Uint8Array): OprfBlindResult {
  const result = getOprfSuite(curve).blind(input);
  return { blind: result.blind, blindedElement: result.blinded };
}

/** Server: evaluate blinded element with secret key. */
export function oprfBlindEvaluate(
  curve: CurveId,
  secretKey: Uint8Array,
  blindedElement: Uint8Array,
): Uint8Array {
  return getOprfSuite(curve).blindEvaluate(secretKey, blindedElement);
}

/** Client: finalize OPRF by unblinding server response. */
export function oprfFinalize(
  curve: CurveId,
  input: Uint8Array,
  blind: Uint8Array,
  evaluatedElement: Uint8Array,
): Uint8Array {
  return getOprfSuite(curve).finalize(input, blind, evaluatedElement);
}

/** Non-blind OPRF evaluation (for testing / server-side credential file). */
export function oprfEvaluate(curve: CurveId, secretKey: Uint8Array, input: Uint8Array): Uint8Array {
  return getOprfSuite(curve).evaluate(secretKey, input);
}
