import { describe, it, expect, beforeEach, vi } from 'vitest';
import { getBackend, setBackend, getBackendName } from '../../src/backend';
import { jsBackend } from '../../src/backend/js';
import { validatePasswordWasm, isWasmAvailable } from '../../src/backend/wasm';
import { CipherSuiteId } from '../../src/suites';
import type { OpaqueBackend } from '../../src/backend/types';

describe('Backend selection', () => {
  beforeEach(() => {
    setBackend(null);
  });

  it('defaults to JS backend (WASM not available)', async () => {
    const backend = await getBackend();
    expect(backend.name).toBe('js');
  });

  it('getBackendName returns null before initialization', () => {
    expect(getBackendName()).toBeNull();
  });

  it('getBackendName returns backend name after initialization', async () => {
    await getBackend();
    expect(getBackendName()).toBe('js');
  });

  it('setBackend overrides auto-detection', async () => {
    const mockBackend: OpaqueBackend = {
      name: 'wasm',
      registrationStart: jsBackend.registrationStart,
      registrationFinish: jsBackend.registrationFinish,
      loginStart: jsBackend.loginStart,
      loginFinish: jsBackend.loginFinish,
    };

    setBackend(mockBackend);
    const backend = await getBackend();
    expect(backend.name).toBe('wasm');
  });

  it('setBackend(null) resets to auto-detection', async () => {
    const mockBackend: OpaqueBackend = {
      name: 'wasm',
      registrationStart: jsBackend.registrationStart,
      registrationFinish: jsBackend.registrationFinish,
      loginStart: jsBackend.loginStart,
      loginFinish: jsBackend.loginFinish,
    };

    setBackend(mockBackend);
    expect(getBackendName()).toBe('wasm');

    setBackend(null);
    expect(getBackendName()).toBeNull();

    const backend = await getBackend();
    expect(backend.name).toBe('js');
  });

  it('concurrent getBackend calls share initialization', async () => {
    const [b1, b2, b3] = await Promise.all([getBackend(), getBackend(), getBackend()]);
    expect(b1).toBe(b2);
    expect(b2).toBe(b3);
  });
});

describe('JS backend', () => {
  it('implements all OpaqueBackend methods', () => {
    expect(jsBackend.name).toBe('js');
    expect(typeof jsBackend.registrationStart).toBe('function');
    expect(typeof jsBackend.registrationFinish).toBe('function');
    expect(typeof jsBackend.loginStart).toBe('function');
    expect(typeof jsBackend.loginFinish).toBe('function');
  });

  it('registrationStart returns request and state', async () => {
    const result = await jsBackend.registrationStart('test-password', CipherSuiteId.P256_SHA256);
    expect(result.request).toBeInstanceOf(Uint8Array);
    expect(result.request.length).toBe(33); // P-256 compressed point
    expect(result.state).toBeDefined();
    expect(result.state.suite).toBe(CipherSuiteId.P256_SHA256);
    expect(result.state.blind).toBeInstanceOf(Uint8Array);
  });

  it('registrationStart produces different requests for same password', async () => {
    const a = await jsBackend.registrationStart('test-password', CipherSuiteId.P256_SHA256);
    const b = await jsBackend.registrationStart('test-password', CipherSuiteId.P256_SHA256);
    expect(a.request).not.toEqual(b.request);
  });

  it('loginStart returns KE1 and state', async () => {
    const result = await jsBackend.loginStart('test-password', CipherSuiteId.P256_SHA256);
    expect(result.ke1).toBeInstanceOf(Uint8Array);
    // KE1 = credential_request(33) + nonce(32) + ephemeral_public(33) = 98
    expect(result.ke1.length).toBe(33 + 32 + 33);
    expect(result.state.suite).toBe(CipherSuiteId.P256_SHA256);
    expect(result.state.blind).toBeInstanceOf(Uint8Array);
    expect(result.state.clientEphemeralSecret).toBeInstanceOf(Uint8Array);
  });
});

describe('WASM Password Validation', () => {
  it('validates valid password (sufficient length + uppercase + lowercase + digit)', async () => {
    const errors = await validatePasswordWasm('Password123');
    expect(errors).toEqual([]);
  });

  it('rejects password that is too short', async () => {
    const errors = await validatePasswordWasm('Pass1', 8);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.includes('characters'))).toBe(true);
  });

  it('rejects password missing uppercase', async () => {
    const errors = await validatePasswordWasm('password123', 8, true);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.includes('Uppercase'))).toBe(true);
  });

  it('rejects password missing lowercase', async () => {
    const errors = await validatePasswordWasm('PASSWORD123', 8, true, true);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.includes('Lowercase'))).toBe(true);
  });

  it('rejects password missing digit', async () => {
    const errors = await validatePasswordWasm('PasswordAbc', 8, true, true, true);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.includes('Digit'))).toBe(true);
  });

  it('allows custom minimum length requirement', async () => {
    const short = 'Pass1';
    const errors = await validatePasswordWasm(short, 5, true, true, true);
    expect(errors).toEqual([]);
  });

  it('allows disabling character class requirements', async () => {
    const errors = await validatePasswordWasm('12345678', 8, false, false, false);
    expect(errors).toEqual([]);
  });

  it('validates multiple constraint violations', async () => {
    const errors = await validatePasswordWasm('abc', 8, true, true, true);
    expect(errors.length).toBeGreaterThanOrEqual(2);
  });

  it('returns empty array for valid password with custom requirements', async () => {
    const errors = await validatePasswordWasm('Test1Pass', 8, true, true, true);
    expect(errors).toEqual([]);
  });

  it('returns WASM availability status', () => {
    const available = isWasmAvailable();
    // Should be false since WASM not loaded in test environment
    expect(typeof available).toBe('boolean');
  });

  it('handles validation with no uppercase requirement', async () => {
    const errors = await validatePasswordWasm('lowercase123', 8, false, true, true);
    expect(errors).toEqual([]);
  });

  it('handles validation with no lowercase requirement', async () => {
    const errors = await validatePasswordWasm('UPPERCASE123', 8, true, false, true);
    expect(errors).toEqual([]);
  });

  it('handles validation with no digit requirement', async () => {
    const errors = await validatePasswordWasm('NoDigitPassword', 8, true, true, false);
    expect(errors).toEqual([]);
  });
});
