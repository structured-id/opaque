/**
 * The OPAQUE backend: the pure-TypeScript implementation over @noble/curves
 * and @noble/hashes, loaded on first use. This package ships no WASM; the
 * WASM acceleration and the zero-knowledge password policy proof live in
 * `@structured-id/opaque-zkpp`. `setBackend` substitutes another backend
 * speaking the same RFC 9807 wire protocol.
 */

import type { OpaqueBackend } from './types.js';

let _backend: OpaqueBackend | null = null;
let _initPromise: Promise<OpaqueBackend> | null = null;

/**
 * Get the OPAQUE backend, initializing on first call.
 *
 * Thread-safe: concurrent calls share the same initialization promise.
 */
export async function getBackend(): Promise<OpaqueBackend> {
  if (_backend) return _backend;

  if (!_initPromise) {
    _initPromise = initBackend();
  }

  return _initPromise;
}

async function initBackend(): Promise<OpaqueBackend> {
  // Pure-TypeScript OPAQUE PAKE backend (no WASM: the WASM acceleration path and
  // the ZKPP method live in the separate AGPL-licensed @structured-id/opaque-zkpp package).
  const { jsBackend } = await import('./js.js');
  _backend = jsBackend;
  return _backend;
}

/**
 * Force a specific backend (for testing or explicit configuration).
 *
 * @param backend - The backend to use, or null to reset to auto-detection.
 */
export function setBackend(backend: OpaqueBackend | null): void {
  _backend = backend;
  _initPromise = null;
}

/**
 * Get the name of the currently active backend, or null if not yet initialized.
 */
export function getBackendName(): 'js' | 'wasm' | null {
  return _backend?.name ?? null;
}

export type { OpaqueBackend } from './types.js';
