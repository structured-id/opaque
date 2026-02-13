import { describe, it, expect } from 'vitest';
import { OpaqueClient } from '../../src/client';
import { CipherSuiteId } from '../../src/suites';

describe('OpaqueClient', () => {
  const client = new OpaqueClient({
    serverId: 'sid.example.com',
    clientId: 'alice@example.com',
    suite: CipherSuiteId.P256_SHA256,
  });

  describe('registrationStart', () => {
    it('returns a request and state', async () => {
      const result = await client.registrationStart('test-password');

      expect(result.request).toBeInstanceOf(Uint8Array);
      expect(result.request.length).toBe(33); // P-256 compressed point
      expect(result.state).toBeDefined();
      expect(result.state.suite).toBe(CipherSuiteId.P256_SHA256);
      expect(result.state.blind).toBeInstanceOf(Uint8Array);
    });

    it('produces different requests for different passwords', async () => {
      const result1 = await client.registrationStart('password-1');
      const result2 = await client.registrationStart('password-2');
      expect(result1.request).not.toEqual(result2.request);
    });

    it('uses fresh randomness each call', async () => {
      const result1 = await client.registrationStart('same-password');
      const result2 = await client.registrationStart('same-password');
      expect(result1.request).not.toEqual(result2.request);
    });
  });

  describe('loginStart', () => {
    it('returns KE1 and state', async () => {
      const result = await client.loginStart('test-password');

      expect(result.ke1).toBeInstanceOf(Uint8Array);
      // KE1 = blinded(33) + nonce(32) + ephemeral_pk(33) = 98
      expect(result.ke1.length).toBe(98);
      expect(result.state.suite).toBe(CipherSuiteId.P256_SHA256);
      expect(result.state.blind).toBeInstanceOf(Uint8Array);
      expect(result.state.clientEphemeralSecret).toBeInstanceOf(Uint8Array);
      expect(result.state.ke1).toBeInstanceOf(Uint8Array);
    });

    it('produces different KE1 for same password', async () => {
      const r1 = await client.loginStart('same-password');
      const r2 = await client.loginStart('same-password');
      expect(r1.ke1).not.toEqual(r2.ke1);
    });
  });

  describe('suite selection', () => {
    it('defaults to RFC standard suite (Ristretto255)', async () => {
      const defaultClient = new OpaqueClient({ serverId: 'test.example.com' });
      // Verify by starting registration — should use Ristretto255 (element size 32)
      const result = await defaultClient.registrationStart('test');
      expect(result.request.length).toBe(32); // ristretto255 element
    });

    it('accepts ristretto255 suite', async () => {
      const r255Client = new OpaqueClient({
        serverId: 'test.example.com',
        suite: CipherSuiteId.RISTRETTO255_SHA512,
      });
      const result = await r255Client.registrationStart('test');
      expect(result.request.length).toBe(32); // ristretto255 element
    });

    it('accepts P384 suite', async () => {
      const p384Client = new OpaqueClient({
        serverId: 'test.example.com',
        suite: CipherSuiteId.P384_SHA384,
      });
      const result = await p384Client.registrationStart('test');
      expect(result.request.length).toBe(49); // P-384 compressed point
    });

    it('accepts P521 suite', async () => {
      const p521Client = new OpaqueClient({
        serverId: 'test.example.com',
        suite: CipherSuiteId.P521_SHA512,
      });
      const result = await p521Client.registrationStart('test');
      expect(result.request.length).toBe(67); // P-521 compressed point
    });
  });
});
