import { describe, it, expect } from 'vitest';
import { OpaqueClient } from '../../src/client';

describe('OpaqueClient', () => {
  const client = new OpaqueClient({ serverId: 'sid.example.com' });

  describe('registrationStart', () => {
    it('returns a request and state', async () => {
      const result = await client.registrationStart('test-password');

      expect(result.request).toBeInstanceOf(Uint8Array);
      expect(result.state).toBeInstanceOf(Uint8Array);
      expect(result.request.length).toBeGreaterThan(0);
      expect(result.state.length).toBeGreaterThan(0);
    });

    it('produces different requests for different passwords', async () => {
      const result1 = await client.registrationStart('password-1');
      const result2 = await client.registrationStart('password-2');

      // Blinded elements should differ (with overwhelming probability)
      expect(result1.request).not.toEqual(result2.request);
    });

    it('uses fresh randomness each call', async () => {
      const result1 = await client.registrationStart('same-password');
      const result2 = await client.registrationStart('same-password');

      // Same password, different blind → different request
      expect(result1.request).not.toEqual(result2.request);
      expect(result1.state).not.toEqual(result2.state);
    });
  });

  describe('loginStart', () => {
    it('returns a request and state', async () => {
      const result = await client.loginStart('test-password');

      expect(result.request).toBeInstanceOf(Uint8Array);
      expect(result.state).toBeInstanceOf(Uint8Array);
    });
  });
});
