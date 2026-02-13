/**
 * OPAQUE registration protocol — client side.
 *
 * Two-step process:
 *   1. registrationStart(password) → blind password, send request to server
 *   2. registrationFinish(password, serverResponse, state) → build record
 *
 * Delegates to the active backend (JS or WASM).
 */
import { getBackend } from './backend/index.js';
import type { CipherSuiteId } from './suites.js';
import type {
  OpaqueState,
  RegistrationStartResult,
  RegistrationFinishResult,
  Identifiers,
} from './types.js';

export type { RegistrationStartResult, RegistrationFinishResult };

export async function registrationStart(
  password: string,
  suite: CipherSuiteId,
): Promise<RegistrationStartResult> {
  const backend = await getBackend();
  return backend.registrationStart(password, suite);
}

export async function registrationFinish(
  password: string,
  serverResponse: Uint8Array,
  state: OpaqueState,
  identifiers: Identifiers,
): Promise<RegistrationFinishResult> {
  const backend = await getBackend();
  return backend.registrationFinish(password, serverResponse, state, identifiers);
}
