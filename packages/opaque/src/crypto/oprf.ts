import { concat, encode, hash } from './utils';

export interface OprfBlindResult {
  blindedElement: Uint8Array;
  blind: Uint8Array;
}

/**
 * Blind a password for OPRF evaluation.
 *
 * @deprecated Use OPRF operations from src/oprf.ts instead.
 * @param password - User password to blind.
 * @returns Blinded element to send to server and blind scalar to preserve.
 */
export async function oprfBlind(password: string): Promise<OprfBlindResult> {
  const input = encode(password);
  const blind = crypto.getRandomValues(new Uint8Array(32));

  // Placeholder: hash(password || blind) as blinded element
  const combined = concat(input, blind);
  const blindedElement = await hash(combined);

  return { blindedElement, blind };
}

/**
 * Finalize OPRF by unblinding the server's response.
 *
 * TODO: Replace with proper OPRF finalization when WASM is ready.
 *
 * @param password - Original user password.
 * @param evaluatedElement - Server's evaluated OPRF element.
 * @param blind - Client blind scalar from oprfBlind.
 * @returns OPRF output bytes (placeholder: SHA-256 of combined inputs).
 */
export async function oprfFinalize(
  password: string,
  evaluatedElement: Uint8Array,
  blind: Uint8Array,
): Promise<Uint8Array> {
  const input = encode(password);
  const combined = concat(input, evaluatedElement, blind);
  return hash(combined);
}
