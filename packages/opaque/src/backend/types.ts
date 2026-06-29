/**
 * Backend interface for OPAQUE cryptographic operations.
 *
 * Two implementations:
 * - `js` — Pure TypeScript using @noble/curves + @noble/hashes
 * - `wasm` — Compiled from Rust `opaque-ke` crate (RFC 9807 compliant, ~5x faster)
 *
 * Both backends produce identical wire protocol output — server is backend-agnostic.
 */
import type { CipherSuiteId } from '../suites.js';
import type {
  OpaqueState,
  RegistrationStartResult,
  RegistrationFinishResult,
  LoginStartResult,
  LoginFinishResult,
  Identifiers,
} from '../types.js';

export interface OpaqueBackend {
  /** Backend identifier. */
  readonly name: 'js' | 'wasm';

  // ── Registration ──

  /** Start registration: blind password via OPRF. */
  registrationStart(password: string, suite: CipherSuiteId): Promise<RegistrationStartResult>;

  /** Finish registration: unblind, build envelope, produce record. */
  registrationFinish(
    password: string,
    response: Uint8Array,
    state: OpaqueState,
    identifiers: Identifiers,
  ): Promise<RegistrationFinishResult>;

  // ── Login ──

  /** Start login: blind password + generate ephemeral AKE keys → KE1. */
  loginStart(password: string, suite: CipherSuiteId): Promise<LoginStartResult>;

  /** Finish login: unblind OPRF, recover credentials, compute 3DH → KE3 + session key. */
  loginFinish(
    password: string,
    ke2: Uint8Array,
    state: OpaqueState,
    identifiers: Identifiers,
  ): Promise<LoginFinishResult>;
}
