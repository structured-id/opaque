import { oprfBlind, oprfFinalize } from './crypto/oprf';
import { buildEnvelope } from './crypto/envelope';

export interface RegistrationStartResult {
  /** The blinded message to send to the server. */
  request: Uint8Array;
  /** Client state to preserve for the finish step. */
  state: Uint8Array;
}

export interface RegistrationFinishResult {
  /** The registration record to send to the server for storage. */
  record: Uint8Array;
  /** The export key derived during registration. */
  exportKey: Uint8Array;
}

/**
 * Start OPAQUE registration (client side).
 *
 * 1. Sample a blind scalar r.
 * 2. Compute blindedElement = r * Hash-to-Group(password).
 * 3. Return { request: blindedElement, state: r }.
 *
 * @param password - User password to register.
 * @param _serverId - Reserved for server identity binding in full implementation.
 * @returns Blinded request and client blind for the finish step.
 */
export async function registrationStart(
  password: string,
  // Reserved for real OPAQUE: serverId will bind the request to server identity
  _serverId: string,
): Promise<RegistrationStartResult> {
  const { blindedElement, blind } = await oprfBlind(password);

  return {
    request: blindedElement,
    state: blind,
  };
}

/**
 * Finish OPAQUE registration (client side).
 *
 * 1. Finalize the OPRF output: unblind server response.
 * 2. Derive keys from the OPRF output.
 * 3. Build envelope containing encrypted credentials.
 * 4. Return registration record + export key.
 *
 * @param password - User password (used for OPRF finalization).
 * @param serverResponse - Server's evaluated OPRF element.
 * @param state - Client blind from registrationStart.
 * @param serverId - Server identity for domain separation.
 * @returns Registration record (placeholder: envelope bytes) and export key.
 */
export async function registrationFinish(
  password: string,
  serverResponse: Uint8Array,
  state: Uint8Array,
  serverId: string,
): Promise<RegistrationFinishResult> {
  const oprfOutput = await oprfFinalize(password, serverResponse, state);
  const { envelope, exportKey } = await buildEnvelope(oprfOutput, serverId);

  // Placeholder: record is the envelope (public key will be added in full implementation)
  const record = envelope.slice();

  return {
    record,
    exportKey,
  };
}
