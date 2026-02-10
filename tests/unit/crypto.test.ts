import { describe, it, expect } from 'vitest';
import { encode, randomBytes, hash, concat, hkdfDerive } from '../../src/crypto/utils';

describe('crypto/utils', () => {
  describe('encode', () => {
    it('encodes string to Uint8Array', () => {
      const result = encode('hello');
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(5);
    });

    it('handles empty string', () => {
      const result = encode('');
      expect(result.length).toBe(0);
    });

    it('handles unicode', () => {
      const result = encode('привет');
      expect(result.length).toBeGreaterThan(6); // UTF-8 multi-byte
    });
  });

  describe('randomBytes', () => {
    it('returns bytes of requested length', () => {
      const result = randomBytes(32);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });

    it('produces different output each call', () => {
      const a = randomBytes(32);
      const b = randomBytes(32);
      expect(a).not.toEqual(b);
    });
  });

  describe('hash', () => {
    it('produces a 32-byte SHA-256 digest', async () => {
      const input = encode('test data');
      const result = await hash(input);
      expect(new Uint8Array(result).length).toBe(32);
    });

    it('is deterministic', async () => {
      const input = encode('same input');
      const a = new Uint8Array(await hash(input));
      const b = new Uint8Array(await hash(input));
      expect(a).toEqual(b);
    });
  });

  describe('concat', () => {
    it('concatenates arrays', () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array([3, 4, 5]);
      const result = concat(a, b);
      expect(Array.from(result)).toEqual([1, 2, 3, 4, 5]);
    });

    it('handles empty arrays', () => {
      const result = concat(new Uint8Array([]), new Uint8Array([1]));
      expect(Array.from(result)).toEqual([1]);
    });
  });

  describe('hkdfDerive', () => {
    it('derives key material of requested length', async () => {
      const ikm = randomBytes(32);
      const result = await hkdfDerive(ikm, 'test-info', 32);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });

    it('produces different output for different info strings', async () => {
      const ikm = randomBytes(32);
      const a = await hkdfDerive(ikm, 'info-a', 32);
      const b = await hkdfDerive(ikm, 'info-b', 32);
      expect(a).not.toEqual(b);
    });

    it('is deterministic for same inputs', async () => {
      const ikm = new Uint8Array(32).fill(42);
      const a = await hkdfDerive(ikm, 'same-info', 32);
      const b = await hkdfDerive(ikm, 'same-info', 32);
      expect(a).toEqual(b);
    });
  });
});
