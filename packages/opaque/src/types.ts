/**
 * Shared types for OPAQUE protocol state and messages.
 */
import type { CipherSuiteId } from './suites.js';

/**
 * Opaque client state preserved between protocol rounds.
 * Internal structure — callers should treat this as opaque.
 */
export interface OpaqueState {
  /** Cipher suite used for this protocol run. */
  readonly suite: CipherSuiteId;
  /** OPRF blind scalar (raw bytes). */
  readonly blind: Uint8Array;
  /** Client ephemeral secret key (for AKE, login only). */
  readonly clientEphemeralSecret?: Uint8Array;
  /** Client ephemeral public key (for AKE, login only). */
  readonly clientEphemeralPublic?: Uint8Array;
  /** Client static secret key (for registration). */
  readonly clientSecret?: Uint8Array;
  /** Client static public key (for registration). */
  readonly clientPublic?: Uint8Array;
  /** KE1 message bytes (for transcript hash in login). */
  readonly ke1?: Uint8Array;
}

/** Registration protocol — client's first message. */
export interface RegistrationStartResult {
  /** The blinded OPRF element to send to server. */
  request: Uint8Array;
  /** Client state to preserve for the finish step. */
  state: OpaqueState;
}

/** Registration protocol — client's final message. */
export interface RegistrationFinishResult {
  /** The registration record to send to server for storage. */
  record: Uint8Array;
  /** Export key derived during registration (for application use). */
  exportKey: Uint8Array;
}

/** Login protocol — client's first message (KE1). */
export interface LoginStartResult {
  /** KE1 message: credential_request || client_nonce || client_ephemeral_public. */
  ke1: Uint8Array;
  /** Client state to preserve for the finish step. */
  state: OpaqueState;
}

/** Login protocol — client's final output. */
export interface LoginFinishResult {
  /** KE3 message: client_mac (sent to server for verification). */
  ke3: Uint8Array;
  /** Session key for subsequent communication. */
  sessionKey: Uint8Array;
  /** Export key derived during login (for application use). */
  exportKey: Uint8Array;
}

/** Server and client identity strings for domain separation. */
export interface Identifiers {
  server: string;
  client: string;
}
