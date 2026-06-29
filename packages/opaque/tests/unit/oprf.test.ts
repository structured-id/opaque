/**
 * OPRF tests (RFC 9497).
 *
 * Tests correctness of blind/evaluate/finalize cycle for all 5 curves.
 * Verifies: blind OPRF = non-blind evaluate, fresh randomness, determinism.
 */
import { describe, it, expect } from 'vitest';
import {
  oprfBlind,
  oprfBlindEvaluate,
  oprfFinalize,
  oprfEvaluate,
  oprfGenerateKeyPair,
} from '../../src/oprf.js';
import { CurveId } from '../../src/suites.js';

const te = new TextEncoder();

const CURVES = [
  { id: CurveId.RISTRETTO255, name: 'Ristretto255', scalarSize: 32, elementSize: 32 },
  { id: CurveId.P256, name: 'P-256', scalarSize: 32, elementSize: 33 },
  { id: CurveId.P384, name: 'P-384', scalarSize: 48, elementSize: 49 },
  { id: CurveId.P521, name: 'P-521', scalarSize: 66, elementSize: 67 },
] as const;

for (const curve of CURVES) {
  describe(`OPRF: ${curve.name}`, () => {
    // ── oprfGenerateKeyPair ──

    it('generateKeyPair returns correct sizes', () => {
      const kp = oprfGenerateKeyPair(curve.id);
      expect(kp.secretKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.secretKey.length).toBe(curve.scalarSize);
      expect(kp.publicKey.length).toBe(curve.elementSize);
    });

    it('generateKeyPair produces different keys each call', () => {
      const a = oprfGenerateKeyPair(curve.id);
      const b = oprfGenerateKeyPair(curve.id);
      expect(a.secretKey).not.toEqual(b.secretKey);
    });

    // ── oprfBlind ──

    it('oprfBlind returns blinded element of correct size', () => {
      const input = te.encode('test-password');
      const result = oprfBlind(curve.id, input);
      expect(result.blind).toBeInstanceOf(Uint8Array);
      expect(result.blindedElement).toBeInstanceOf(Uint8Array);
      expect(result.blind.length).toBe(curve.scalarSize);
      expect(result.blindedElement.length).toBe(curve.elementSize);
    });

    it('oprfBlind: fresh randomness each call', () => {
      const input = te.encode('same-password');
      const a = oprfBlind(curve.id, input);
      const b = oprfBlind(curve.id, input);
      expect(a.blindedElement).not.toEqual(b.blindedElement);
      expect(a.blind).not.toEqual(b.blind);
    });

    it('oprfBlind: different inputs → different blinded elements', () => {
      const a = oprfBlind(curve.id, te.encode('password-1'));
      const b = oprfBlind(curve.id, te.encode('password-2'));
      expect(a.blindedElement).not.toEqual(b.blindedElement);
    });

    // ── Blind + Evaluate + Finalize roundtrip ──

    it('blind/evaluate/finalize roundtrip produces consistent output', () => {
      const kp = oprfGenerateKeyPair(curve.id);
      const input = te.encode('test-password');

      const { blind, blindedElement } = oprfBlind(curve.id, input);
      const evaluated = oprfBlindEvaluate(curve.id, kp.secretKey, blindedElement);
      const output = oprfFinalize(curve.id, input, blind, evaluated);

      expect(output).toBeInstanceOf(Uint8Array);
      expect(output.length).toBeGreaterThan(0);
    });

    it('blind OPRF output matches non-blind evaluate', () => {
      const kp = oprfGenerateKeyPair(curve.id);
      const input = te.encode('match-test-password');

      // Blind path
      const { blind, blindedElement } = oprfBlind(curve.id, input);
      const evaluated = oprfBlindEvaluate(curve.id, kp.secretKey, blindedElement);
      const blindOutput = oprfFinalize(curve.id, input, blind, evaluated);

      // Non-blind path
      const directOutput = oprfEvaluate(curve.id, kp.secretKey, input);

      expect(blindOutput).toEqual(directOutput);
    });

    it('different keys → different OPRF outputs', () => {
      const kp1 = oprfGenerateKeyPair(curve.id);
      const kp2 = oprfGenerateKeyPair(curve.id);
      const input = te.encode('test-password');

      const out1 = oprfEvaluate(curve.id, kp1.secretKey, input);
      const out2 = oprfEvaluate(curve.id, kp2.secretKey, input);

      expect(out1).not.toEqual(out2);
    });

    it('different inputs → different OPRF outputs', () => {
      const kp = oprfGenerateKeyPair(curve.id);

      const out1 = oprfEvaluate(curve.id, kp.secretKey, te.encode('password-1'));
      const out2 = oprfEvaluate(curve.id, kp.secretKey, te.encode('password-2'));

      expect(out1).not.toEqual(out2);
    });

    it('same key + same input → same OPRF output', () => {
      const kp = oprfGenerateKeyPair(curve.id);
      const input = te.encode('deterministic-test');

      const out1 = oprfEvaluate(curve.id, kp.secretKey, input);
      const out2 = oprfEvaluate(curve.id, kp.secretKey, input);

      expect(out1).toEqual(out2);
    });

    it('blind OPRF with same key but different blinds → same final output', () => {
      const kp = oprfGenerateKeyPair(curve.id);
      const input = te.encode('blind-consistency');

      const r1 = oprfBlind(curve.id, input);
      const e1 = oprfBlindEvaluate(curve.id, kp.secretKey, r1.blindedElement);
      const o1 = oprfFinalize(curve.id, input, r1.blind, e1);

      const r2 = oprfBlind(curve.id, input);
      const e2 = oprfBlindEvaluate(curve.id, kp.secretKey, r2.blindedElement);
      const o2 = oprfFinalize(curve.id, input, r2.blind, e2);

      // Different blinds, but same final output (blinding cancels)
      expect(r1.blind).not.toEqual(r2.blind);
      expect(o1).toEqual(o2);
    });

    // ── oprfBlindEvaluate ──

    it('blindEvaluate returns element of correct size', () => {
      const kp = oprfGenerateKeyPair(curve.id);
      const { blindedElement } = oprfBlind(curve.id, te.encode('test'));
      const evaluated = oprfBlindEvaluate(curve.id, kp.secretKey, blindedElement);
      expect(evaluated).toBeInstanceOf(Uint8Array);
      expect(evaluated.length).toBe(curve.elementSize);
    });
  });
}
