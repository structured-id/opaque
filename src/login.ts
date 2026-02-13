/**
 * OPAQUE login protocol — client side.
 *
 * Two-step process:
 *   1. loginStart(password) → blind password + AKE ephemeral keys → KE1
 *   2. loginFinish(password, ke2, state) → recover credentials, 3DH → KE3 + session key
 *
 * Delegates to the active backend (JS or WASM).
 */
import { getBackend } from './backend/index.js';
import type { CipherSuiteId } from './suites.js';
import type { OpaqueState, LoginStartResult, LoginFinishResult, Identifiers } from './types.js';

export type { LoginStartResult, LoginFinishResult };

export async function loginStart(
  password: string,
  suite: CipherSuiteId,
): Promise<LoginStartResult> {
  const backend = await getBackend();
  return backend.loginStart(password, suite);
}

export async function loginFinish(
  password: string,
  ke2: Uint8Array,
  state: OpaqueState,
  identifiers: Identifiers,
): Promise<LoginFinishResult> {
  const backend = await getBackend();
  return backend.loginFinish(password, ke2, state, identifiers);
}
