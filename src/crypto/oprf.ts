import { encode, hash } from './utils';

export interface OprfBlindResult {
  blindedElement: Uint8Array;
  blind: Uint8Array;
}

/**
 * Blind a password for OPRF evaluation.
 *
 * TODO: Replace with proper ristretto255/Pallas OPRF when WASM is ready.
 * Current implementation is a placeholder using HKDF.
 */
export async function oprfBlind(password: string): Promise<OprfBlindResult> {
  const input = encode(password);
  const blind = crypto.getRandomValues(new Uint8Array(32));

  // Placeholder: hash(password || blind) as blinded element
  const combined = new Uint8Array([...input, ...blind]);
  const blindedElement = new Uint8Array(await hash(combined));

  return { blindedElement, blind };
}

/**
 * Finalize OPRF by unblinding the server's response.
 *
 * TODO: Replace with proper OPRF finalization when WASM is ready.
 */
export async function oprfFinalize(
  password: string,
  evaluatedElement: Uint8Array,
  blind: Uint8Array,
): Promise<Uint8Array> {
  const input = encode(password);
  const combined = new Uint8Array([...input, ...evaluatedElement, ...blind]);
  return new Uint8Array(await hash(combined));
}
