/**
 * Cipher suite definitions tests.
 *
 * Tests: getSuite, getSuiteByCurve, predefined suites, enum values.
 */
import { describe, it, expect } from 'vitest';
import {
  CurveId,
  CipherSuiteId,
  DEFAULT_SUITE,
  SUITES,
  getSuite,
  getSuiteByCurve,
  RISTRETTO255_SHA512,
  P256_SHA256,
  P384_SHA384,
  P521_SHA512,
} from '../../src/suites.js';

describe('CipherSuiteId enum', () => {
  it('RFC standard suites have low IDs', () => {
    expect(CipherSuiteId.RISTRETTO255_SHA512).toBe(0x0001);
    expect(CipherSuiteId.P256_SHA256).toBe(0x0002);
  });

  it('SID extended suites have 0x1000+ IDs', () => {
    expect(CipherSuiteId.P384_SHA384).toBe(0x1003);
    expect(CipherSuiteId.P521_SHA512).toBe(0x1004);
  });
});

describe('CurveId enum', () => {
  it('matches proto CurveId values', () => {
    expect(CurveId.RISTRETTO255).toBe(1);
    expect(CurveId.P256).toBe(2);
    expect(CurveId.P384).toBe(3);
    expect(CurveId.P521).toBe(4);
  });
});

describe('DEFAULT_SUITE', () => {
  it('defaults to Ristretto255 (public npm default)', () => {
    expect(DEFAULT_SUITE).toBe(CipherSuiteId.RISTRETTO255_SHA512);
  });
});

describe('SUITES map', () => {
  it('contains all defined suites', () => {
    expect(SUITES.size).toBeGreaterThan(0);
  });

  it('all public suites are accessible by ID', () => {
    expect(SUITES.get(CipherSuiteId.RISTRETTO255_SHA512)).toBe(RISTRETTO255_SHA512);
    expect(SUITES.get(CipherSuiteId.P256_SHA256)).toBe(P256_SHA256);
    expect(SUITES.get(CipherSuiteId.P384_SHA384)).toBe(P384_SHA384);
    expect(SUITES.get(CipherSuiteId.P521_SHA512)).toBe(P521_SHA512);
  });
});

describe('getSuite', () => {
  it('returns correct suite for each ID', () => {
    expect(getSuite(CipherSuiteId.RISTRETTO255_SHA512).name).toBe('OPAQUE-Ristretto255-SHA512');
    expect(getSuite(CipherSuiteId.P256_SHA256).name).toBe('OPAQUE-P256-SHA256');
    expect(getSuite(CipherSuiteId.P384_SHA384).name).toBe('SID-P384-SHA384');
    expect(getSuite(CipherSuiteId.P521_SHA512).name).toBe('SID-P521-SHA512');
  });

  it('throws for unknown suite ID', () => {
    expect(() => getSuite(0x9999 as CipherSuiteId)).toThrow('Unknown cipher suite');
  });
});

describe('getSuiteByCurve', () => {
  it('returns correct suite for each public curve', () => {
    expect(getSuiteByCurve(CurveId.RISTRETTO255).id).toBe(CipherSuiteId.RISTRETTO255_SHA512);
    expect(getSuiteByCurve(CurveId.P256).id).toBe(CipherSuiteId.P256_SHA256);
    expect(getSuiteByCurve(CurveId.P384).id).toBe(CipherSuiteId.P384_SHA384);
    expect(getSuiteByCurve(CurveId.P521).id).toBe(CipherSuiteId.P521_SHA512);
  });

  it('throws for unknown curve', () => {
    expect(() => getSuiteByCurve(999 as CurveId)).toThrow('No suite for curve');
  });
});

describe('Predefined suite properties', () => {
  const suites = [
    { suite: RISTRETTO255_SHA512, curve: CurveId.RISTRETTO255, hash: 'SHA-512', standard: true },
    { suite: P256_SHA256, curve: CurveId.P256, hash: 'SHA-256', standard: true },
    { suite: P384_SHA384, curve: CurveId.P384, hash: 'SHA-384', standard: false },
    { suite: P521_SHA512, curve: CurveId.P521, hash: 'SHA-512', standard: false },
  ];

  for (const { suite, curve, hash, standard } of suites) {
    describe(suite.name, () => {
      it('has correct curve', () => {
        expect(suite.curve).toBe(curve);
      });

      it('has correct hash', () => {
        expect(suite.hash).toBe(hash);
      });

      it(`isStandard = ${standard}`, () => {
        expect(suite.isStandard).toBe(standard);
      });

      it('has positive element/scalar/nonce/mac/key sizes', () => {
        expect(suite.elementSize).toBeGreaterThan(0);
        expect(suite.scalarSize).toBeGreaterThan(0);
        expect(suite.nonceSize).toBe(32);
        expect(suite.macSize).toBeGreaterThan(0);
        expect(suite.keySize).toBe(32);
        expect(suite.oprfOutputSize).toBeGreaterThan(0);
      });
    });
  }
});
