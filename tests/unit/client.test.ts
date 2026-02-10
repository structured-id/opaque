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

  describe('registrationFinish', () => {
    it('returns a record and export key', async () => {
      const { state } = await client.registrationStart('test-password');
      const fakeServerResponse = new Uint8Array(32).fill(7);

      const result = await client.registrationFinish('test-password', fakeServerResponse, state);

      expect(result.record).toBeInstanceOf(Uint8Array);
      expect(result.exportKey).toBeInstanceOf(Uint8Array);
      expect(result.record.length).toBeGreaterThan(0);
      expect(result.exportKey.length).toBe(32);
    });

    it('is deterministic for same inputs', async () => {
      const state = new Uint8Array(32).fill(1);
      const serverResponse = new Uint8Array(32).fill(2);

      const a = await client.registrationFinish('password', serverResponse, state);
      const b = await client.registrationFinish('password', serverResponse, state);

      expect(a.record).toEqual(b.record);
      expect(a.exportKey).toEqual(b.exportKey);
    });
  });

  describe('loginStart', () => {
    it('returns a request and state', async () => {
      const result = await client.loginStart('test-password');

      expect(result.request).toBeInstanceOf(Uint8Array);
      expect(result.state).toBeInstanceOf(Uint8Array);
    });
  });

  describe('loginFinish', () => {
    it('returns finalization, session key, and export key', async () => {
      const { state } = await client.loginStart('test-password');
      const fakeServerResponse = new Uint8Array(32).fill(9);

      const result = await client.loginFinish('test-password', fakeServerResponse, state);

      expect(result.finalization).toBeInstanceOf(Uint8Array);
      expect(result.sessionKey).toBeInstanceOf(Uint8Array);
      expect(result.exportKey).toBeInstanceOf(Uint8Array);
      expect(result.finalization.length).toBe(32);
      expect(result.sessionKey.length).toBe(32);
      expect(result.exportKey.length).toBe(32);
    });

    it('produces different keys for different server IDs', async () => {
      const state = new Uint8Array(32).fill(1);
      const serverResponse = new Uint8Array(32).fill(2);

      const client1 = new OpaqueClient({ serverId: 'server-a.example.com' });
      const client2 = new OpaqueClient({ serverId: 'server-b.example.com' });

      const a = await client1.loginFinish('password', serverResponse, state);
      const b = await client2.loginFinish('password', serverResponse, state);

      expect(a.sessionKey).not.toEqual(b.sessionKey);
    });

    it('is deterministic for same inputs', async () => {
      const state = new Uint8Array(32).fill(1);
      const serverResponse = new Uint8Array(32).fill(2);

      const a = await client.loginFinish('password', serverResponse, state);
      const b = await client.loginFinish('password', serverResponse, state);

      expect(a.sessionKey).toEqual(b.sessionKey);
      expect(a.exportKey).toEqual(b.exportKey);
      expect(a.finalization).toEqual(b.finalization);
    });
  });
});
