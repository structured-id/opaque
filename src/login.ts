import { oprfBlind, oprfFinalize } from './crypto/oprf';
import { deriveKeys } from './crypto/ake';

export interface LoginStartResult {
  /** The credential request to send to the server. */
  request: Uint8Array;
  /** Client state to preserve for the finish step. */
  state: Uint8Array;
}

export interface LoginFinishResult {
  /** The credential finalization message to send to the server. */
  finalization: Uint8Array;
  /** The session key for subsequent communication. */
  sessionKey: Uint8Array;
  /** The export key derived during login. */
  exportKey: Uint8Array;
}

/**
 * Start OPAQUE login (client side).
 *
 * 1. Blind the password (same as registration start).
 * 2. Return credential request + client state for loginFinish.
 *
 * TODO: Add ephemeral key exchange material when AKE is implemented.
 */
export async function loginStart(
  password: string,
  // Reserved for real OPAQUE: serverId will bind the request to server identity
  _serverId: string,
): Promise<LoginStartResult> {
  const { blindedElement, blind } = await oprfBlind(password);

  return {
    request: blindedElement,
    state: blind,
  };
}

/**
 * Finish OPAQUE login (client side).
 *
 * 1. Unblind the server's OPRF response.
 * 2. Recover credentials from the envelope.
 * 3. Perform authenticated key exchange.
 * 4. Derive session key.
 */
export async function loginFinish(
  password: string,
  serverResponse: Uint8Array,
  state: Uint8Array,
  serverId: string,
): Promise<LoginFinishResult> {
  const oprfOutput = await oprfFinalize(password, serverResponse, state);
  const { sessionKey, exportKey, finalization } = await deriveKeys(oprfOutput, serverId);

  return {
    finalization,
    sessionKey,
    exportKey,
  };
}
