import { registrationStart, registrationFinish } from './registration';
import type { RegistrationStartResult, RegistrationFinishResult } from './registration';
import { loginStart, loginFinish } from './login';
import type { LoginStartResult, LoginFinishResult } from './login';

export interface OpaqueClientConfig {
  /** Server identity (usually the domain, e.g. "sid.example.com") */
  serverId: string;
}

/**
 * OPAQUE (RFC 9807) client for browser and Node.js environments.
 *
 * Handles the client side of OPAQUE registration and login flows
 * using the WebCrypto API for core operations.
 */
export class OpaqueClient {
  private readonly serverId: string;

  constructor(config: OpaqueClientConfig) {
    this.serverId = config.serverId;
  }

  /**
   * Start the registration process.
   * Generates a registration request to send to the server.
   */
  async registrationStart(password: string): Promise<RegistrationStartResult> {
    return registrationStart(password, this.serverId);
  }

  /**
   * Finish the registration process.
   * Processes the server's registration response and produces the final record.
   */
  async registrationFinish(
    password: string,
    serverResponse: Uint8Array,
    state: Uint8Array,
  ): Promise<RegistrationFinishResult> {
    return registrationFinish(password, serverResponse, state, this.serverId);
  }

  /**
   * Start the login process.
   * Generates a credential request to send to the server.
   */
  async loginStart(password: string): Promise<LoginStartResult> {
    return loginStart(password, this.serverId);
  }

  /**
   * Finish the login process.
   * Processes the server's credential response and derives session keys.
   */
  async loginFinish(
    password: string,
    serverResponse: Uint8Array,
    state: Uint8Array,
  ): Promise<LoginFinishResult> {
    return loginFinish(password, serverResponse, state, this.serverId);
  }
}
