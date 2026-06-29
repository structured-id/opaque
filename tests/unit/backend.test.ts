import { describe, it, expect, beforeEach } from 'vitest';
import { getBackend, setBackend, getBackendName } from '../../src/backend';
import { jsBackend } from '../../src/backend/js';
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
