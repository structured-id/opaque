import { getBackend } from './backend/index.js';
import type {
  RegistrationStartResult,
  RegistrationFinishResult,
  LoginStartResult,
  LoginFinishResult,
  Identifiers,
  OpaqueState,
} from './types.js';
import { CipherSuiteId, DEFAULT_SUITE } from './suites.js';

export interface OpaqueClientConfig {
  /** Server identity (usually the domain, e.g. "sid.example.com"). */
  serverId: string;
  /** Client identity (usually the user identifier, e.g. email). */
  clientId?: string;
  /** Cipher suite to use. Defaults to RISTRETTO255-SHA512 (RFC 9807). */
  suite?: CipherSuiteId;
}

/**
 * OPAQUE (RFC 9807) client for browser and Node.js environments.
 *
 * Handles the client side of OPAQUE registration and login flows.
 * Supports both RFC 9807 standard suites and SID extended suites.
 */
export class OpaqueClient {
  private readonly identifiers: Identifiers;
  private readonly suite: CipherSuiteId;

  constructor(config: OpaqueClientConfig) {
    this.identifiers = {
      server: config.serverId,
      client: config.clientId ?? '',
    };
    this.suite = config.suite ?? DEFAULT_SUITE;
  }

  /**
   * Start registration: blind the password via OPRF.
   * Send the returned `request` to the server.
   */
  async registrationStart(password: string): Promise<RegistrationStartResult> {
    const backend = await getBackend();
    return backend.registrationStart(password, this.suite);
  }

  /**
   * Finish registration: process server response, build envelope.
   * Send the returned `record` to the server for storage.
   */
  async registrationFinish(
    password: string,
    serverResponse: Uint8Array,
    state: OpaqueState,
  ): Promise<RegistrationFinishResult> {
    const backend = await getBackend();
    return backend.registrationFinish(password, serverResponse, state, this.identifiers);
  }

  /**
   * Start login: blind password + generate ephemeral AKE keys.
   * Send the returned `ke1` to the server.
   */
  async loginStart(password: string): Promise<LoginStartResult> {
    const backend = await getBackend();
    return backend.loginStart(password, this.suite);
  }

  /**
   * Finish login: process server KE2, recover credentials, complete 3DH.
   * Send the returned `ke3` to the server. Use `sessionKey` for subsequent communication.
   */
  async loginFinish(
    password: string,
    ke2: Uint8Array,
    state: OpaqueState,
  ): Promise<LoginFinishResult> {
    const backend = await getBackend();
    return backend.loginFinish(password, ke2, state, this.identifiers);
  }
}
