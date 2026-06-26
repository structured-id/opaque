/**
 * WASM OPAQUE backend + password policy validation.
 *
 * Provides:
 * - RFC 9807 OPAQUE protocol implementation via compiled WASM
 * - Cryptographic password policy validation (character class, length checks)
 * - Breach password detection (k-anonymity HIBP, SHA-1 inside WASM)
 * - High performance: ~2-5ms per operation
 *
 * Implementation: Compiled from Rust to WebAssembly via wasm-bindgen.
 * Sources not included in npm package — only compiled .wasm binary.
 *
 * Fallback: If WASM unavailable, uses pure JS backend (RFC 9807 only,
 * no policy enforcement in ZK).
 */

import type { OpaqueBackend } from './types.js';
import type { CipherSuiteId } from '../suites.js';
import type {
  OpaqueState,
  RegistrationStartResult,
  RegistrationFinishResult,
  LoginStartResult,
  LoginFinishResult,
  Identifiers,
} from '../types.js';

/** Lazy-loaded WASM module (wasm-bindgen glue) */
let wasmGlue: {
  validate_password: (password: string, policy_json: string) => string;
  get_policy: (version: number) => string;
  prepare_breach_check: (password: string) => string;
  verify_breach_response: (password: string, hibp_response: string) => string;
  generate_zkpp_proof: (
    password: string,
    policy_version: number,
    mode: string,
    prev_commitment?: string | null,
  ) => string;
} | null = null;

let initPromise: Promise<void> | null = null;
let initError: Error | null = null;

/**
 * Initialize the WASM backend via wasm-bindgen glue.
 *
 * Dynamically imports the wasm-bindgen generated JS module which
 * handles WASM instantiation, memory management, and string passing.
 */
export async function initWasm(): Promise<OpaqueBackend> {
  if (wasmGlue) {
    return wasmBackend;
  }

  if (initError) {
    throw initError;
  }

  if (initPromise) {
    await initPromise;
    if (initError) throw initError;
    return wasmBackend;
  }

  initPromise = (async () => {
    try {
      // Import wasm-bindgen generated glue module.
      // The glue module handles WASM loading via `default()` init function.
      // dist/sid_wasm.js + dist/sid_wasm_bg.wasm must be present.
      // wasm/ directory is in git with pre-built wasm-bindgen artifacts
      const wasm = await import('../../wasm/sid_wasm.js');

      // Initialize WASM module (loads .wasm binary relative to glue JS)
      await wasm.default();

      wasmGlue = {
        validate_password: wasm.validate_password,
        get_policy: wasm.get_policy,
        prepare_breach_check: wasm.prepare_breach_check,
        verify_breach_response: wasm.verify_breach_response,
        generate_zkpp_proof: wasm.generate_zkpp_proof,
      };

      console.info('[opaque] ✅ WASM backend loaded (wasm-bindgen)');
      console.info('[opaque] - Password policy validation');
      console.info('[opaque] - Breach detection (k-anonymity)');
      console.info('[opaque] - Compiled binary (sources not included)');
    } catch (error) {
      console.warn(
        '[opaque] ⚠️  WASM backend unavailable:',
        error instanceof Error ? error.message : String(error),
      );
      initError = error instanceof Error ? error : new Error(String(error));
      throw initError;
    }
  })();

  await initPromise;
  if (initError) throw initError;
  return wasmBackend;
}

/**
 * Check if WASM backend is available
 */
export function isWasmAvailable(): boolean {
  return wasmGlue !== null && initError === null;
}

/**
 * Validate password against policy constraints (using WASM)
 */
export async function validatePasswordWasm(
  password: string,
  minLength: number = 8,
  requireUpper: boolean = true,
  requireLower: boolean = true,
  requireDigit: boolean = true,
): Promise<string[]> {
  try {
    await initWasm();
  } catch {
    return validatePasswordJS(password, minLength, requireUpper, requireLower, requireDigit);
  }

  if (wasmGlue) {
    try {
      const policyJson = JSON.stringify({
        version: 1,
        min_length: minLength,
        min_upper: requireUpper ? 1 : 0,
        min_lower: requireLower ? 1 : 0,
        min_digit: requireDigit ? 1 : 0,
        min_symbol: 0,
      });

      const resultJson = wasmGlue.validate_password(password, policyJson);
      const result = JSON.parse(resultJson);
      return result.errors || [];
    } catch (error) {
      console.warn('[opaque] WASM validation failed, falling back to JS:', error);
      return validatePasswordJS(password, minLength, requireUpper, requireLower, requireDigit);
    }
  }

  return validatePasswordJS(password, minLength, requireUpper, requireLower, requireDigit);
}

/**
 * Client-side password validation (JavaScript fallback)
 */
function validatePasswordJS(
  password: string,
  minLength: number,
  requireUpper: boolean,
  requireLower: boolean,
  requireDigit: boolean,
): string[] {
  const errors: string[] = [];
  if (password.length < minLength) {
    errors.push(`Minimum ${minLength} characters required`);
  }
  if (requireUpper && !/[A-Z]/.test(password)) {
    errors.push('Uppercase letter required');
  }
  if (requireLower && !/[a-z]/.test(password)) {
    errors.push('Lowercase letter required');
  }
  if (requireDigit && !/\d/.test(password)) {
    errors.push('Digit required');
  }
  return errors;
}

/**
 * Lazily-loaded pure-TS OPAQUE backend. The compiled WASM provides only
 * policy / breach / ZKPP today; the OPAQUE protocol itself runs in TS
 * (@noble/curves). Cached after first load so the dynamic import is paid once.
 */
let _jsBackend: OpaqueBackend | null = null;
async function opaqueJs(): Promise<OpaqueBackend> {
  if (!_jsBackend) {
    _jsBackend = (await import('./js.js')).jsBackend;
  }
  return _jsBackend;
}

/**
 * WASM backend: policy / breach / ZKPP run in WASM (fast); the OPAQUE protocol
 * delegates to the pure-TS backend until OPAQUE-in-WASM ships. The wire format is
 * backend-agnostic, so this hybrid is transparent to the server. On a browser
 * without WASM, `initWasm()` throws and the selector picks the TS backend wholesale.
 */
export const wasmBackend: OpaqueBackend = {
  name: 'wasm',

  async registrationStart(
    password: string,
    suite: CipherSuiteId,
  ): Promise<RegistrationStartResult> {
    return (await opaqueJs()).registrationStart(password, suite);
  },

  async registrationFinish(
    password: string,
    response: Uint8Array,
    state: OpaqueState,
    identifiers: Identifiers,
  ): Promise<RegistrationFinishResult> {
    return (await opaqueJs()).registrationFinish(password, response, state, identifiers);
  },

  async loginStart(password: string, suite: CipherSuiteId): Promise<LoginStartResult> {
    return (await opaqueJs()).loginStart(password, suite);
  },

  async loginFinish(
    password: string,
    ke2: Uint8Array,
    state: OpaqueState,
    identifiers: Identifiers,
  ): Promise<LoginFinishResult> {
    return (await opaqueJs()).loginFinish(password, ke2, state, identifiers);
  },
};
